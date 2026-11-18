package cloudhypervisor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// readLimit is the most of an image the check reads. A qcow2 header and its extensions live in
// the first cluster, and a cluster is at most 2 MiB.
const readLimit = 1 << 21

// imageFormat is how img will be converted. format is "raw" or "qcow2". A qcow2 that names a
// backing file or an external data file, or that is encrypted, and any other disk format, is
// refused. dstSize, when set, refuses an image that does not fit the disk.
func (r *Runtime) imageFormat(img string, dstSize int64) (string, error) {
	format, virt, err := inspectImage(r.Host, img)
	if err != nil { // refused: not raw, or a qcow2 with a backing file, an external data file, or encryption
		return "", fmt.Errorf("%s: %w", img, err)
	}
	if dstSize > 0 && virt > uint64(dstSize) { // the image does not fit the disk
		return "", fmt.Errorf("%s is %d bytes and the disk is %d bytes: it does not fit", img, virt, dstSize)
	}
	return format, nil
}

// inspectImage reads the start of path and decides raw or a plain qcow2. The size is the qcow2
// virtual size, or the file's length for raw.
func inspectImage(h Host, path string) (format string, virtual uint64, err error) {
	b, err := readPrefix(h, path, readLimit)
	if err != nil {
		return "", 0, err
	}
	if len(b) >= 4 && string(b[:4]) == "QFI\xfb" {
		return checkQcow2(b)
	}
	if why := foreignDisk(b); why != "" { // VMDK, VHD, VHDX, VDI and the rest are refused
		return "", 0, refuseImage(why)
	}
	n, err := fileSize(h, path)
	if err != nil {
		return "", 0, err
	}
	return "raw", uint64(n), nil
}

func refuseImage(why string) error {
	return fmt.Errorf("%s: only a raw disk, or a qcow2 with no backing file, no external data file and no encryption, can be a silo's disk", why)
}

func foreignDisk(b []byte) string {
	switch {
	case len(b) >= 4 && string(b[:4]) == "KDMV":
		return "VMDK is not a silo disk"
	case bytesHasPrefix(b, "# Disk DescriptorFile"):
		return "VMDK is not a silo disk"
	case bytesHasPrefix(b, "conectix"):
		return "VHD is not a silo disk"
	case bytesHasPrefix(b, "vhdxfile"):
		return "VHDX is not a silo disk"
	case bytesHasPrefix(b, "QED\x00"):
		return "QED is not a silo disk"
	case len(b) >= 0x40 && bytesHasPrefix(b[0x40:], "<<< Oracle VM VirtualBox Disk Image >>>"):
		return "VDI is not a silo disk"
	case bytesHasPrefix(b, "WithoutFreeSpace") || bytesHasPrefix(b, "WithouFreSpacExt"):
		return "a parallels disk is not a silo disk"
	default:
		return ""
	}
}

func bytesHasPrefix(b []byte, s string) bool {
	return len(b) >= len(s) && string(b[:len(s)]) == s
}

const (
	qcow2Dirty        = uint64(1) << 0
	qcow2Corrupt      = uint64(1) << 1
	qcow2ExternalData = uint64(1) << 2
	qcow2Compression  = uint64(1) << 3
	qcow2ExtendedL2   = uint64(1) << 4
)

func checkQcow2(b []byte) (string, uint64, error) {
	if len(b) < 72 {
		return "", 0, refuseImage("the qcow2 header is truncated")
	}
	version := binary.BigEndian.Uint32(b[4:8])
	if version != 2 && version != 3 {
		return "", 0, refuseImage(fmt.Sprintf("qcow2 version %d is not 2 or 3", version))
	}
	backingOff := binary.BigEndian.Uint64(b[8:16])
	backingSize := binary.BigEndian.Uint32(b[16:20])
	if backingOff != 0 || backingSize != 0 { // a backing file is refused
		return "", 0, refuseImage("the image names a backing file")
	}
	bits := binary.BigEndian.Uint32(b[20:24])
	if bits < 9 || bits > 21 {
		return "", 0, refuseImage(fmt.Sprintf("qcow2 cluster_bits %d is not between 9 and 21", bits))
	}
	virtual := binary.BigEndian.Uint64(b[24:32])
	if virtual == 0 {
		return "", 0, refuseImage("the qcow2 virtual size is empty")
	}
	if crypt := binary.BigEndian.Uint32(b[32:36]); crypt != 0 { // encryption is refused
		return "", 0, refuseImage("the image is encrypted")
	}
	headerLen := uint32(72)
	if version == 3 {
		if len(b) < 104 {
			return "", 0, refuseImage("the qcow2 header is truncated")
		}
		incompat := binary.BigEndian.Uint64(b[72:80])
		allowed := qcow2Dirty | qcow2Compression | qcow2ExtendedL2
		if incompat&^allowed != 0 {
			return "", 0, refuseImage("the image names an external data file, is marked corrupt, or uses a qcow2 feature this host does not accept")
		}
		headerLen = binary.BigEndian.Uint32(b[100:104])
		if headerLen < 104 {
			return "", 0, refuseImage("the qcow2 header is truncated")
		}
	}
	if err := qcow2Extensions(b, headerLen); err != nil {
		return "", 0, err
	}
	return "qcow2", virtual, nil
}

func qcow2Extensions(b []byte, headerLen uint32) error {
	if headerLen > uint32(len(b)) {
		return refuseImage("the qcow2 header is truncated")
	}
	off := int((headerLen + 7) &^ 7)
	for off+8 <= len(b) {
		typ := binary.BigEndian.Uint32(b[off : off+4])
		n := binary.BigEndian.Uint32(b[off+4 : off+8])
		off += 8
		if typ == 0 {
			return nil
		}
		switch typ {
		case 0xe2792aca:
			return refuseImage("the image names a backing file")
		case 0x0537be77:
			return refuseImage("the image is encrypted")
		case 0x44415441:
			return refuseImage("the image names an external data file")
		}
		if int(n) < 0 || off > len(b) || int(n) > len(b)-off {
			return refuseImage("the qcow2 header is truncated")
		}
		off += int(n)
		if extra := off % 8; extra != 0 {
			off += 8 - extra
		}
	}
	return nil
}

func readPrefix(h Host, path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err == nil {
		defer func() { _ = f.Close() }()
		buf := make([]byte, n)
		k, rerr := io.ReadFull(f, buf)
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			return buf[:k], nil
		}
		return buf[:k], rerr
	}
	if !errors.Is(err, os.ErrNotExist) || h == nil {
		return nil, err
	}
	b, rerr := h.ReadFile(path)
	if rerr != nil {
		return nil, rerr
	}
	if len(b) > n {
		b = b[:n]
	}
	return b, nil
}

func fileSize(h Host, path string) (int64, error) {
	st, err := os.Stat(path)
	if err == nil {
		return st.Size(), nil
	}
	if !errors.Is(err, os.ErrNotExist) || h == nil {
		return 0, err
	}
	b, rerr := h.ReadFile(path)
	if rerr != nil {
		return 0, rerr
	}
	return int64(len(b)), nil
}

// mustBeMounted refuses a folder that is not a mount, so a root disk is never written beside the
// volume that should hold it.
func (r *Runtime) mustBeMounted(ctx context.Context, dir string) error {
	out, err := r.Host.Run(ctx, "mountpoint", "-q", dir)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s is not a mount, so the root disk is not written there (%s)", dir, msg)
	}
	return nil
}

// convertImage converts with the format inspectImage decided, as kevaso-img, which is shown only
// the image and the target. The unit is bound to kevasod, so a restart stops a half-made convert.
func (r *Runtime) convertImage(ctx context.Context, rest []string) error {
	img, dst, err := convertEnds(rest)
	if err != nil {
		return err
	}
	format, err := r.imageFormat(img, 0)
	if err != nil {
		return err
	}
	if err = r.grantConvert(ctx, img, dst); err != nil {
		return err
	}
	defer r.revokeConvert(img, dst)
	argv := []string{"convert", "-f", format}
	argv = append(argv, rest...)
	return r.runConfined(ctx, img, dst, argv)
}

func convertEnds(args []string) (img, dst string, err error) {
	if len(args) < 2 {
		return "", "", errors.New("qemu-img convert: an image and a target are required")
	}
	return args[len(args)-2], args[len(args)-1], nil
}

// grantConvert lets kevaso-img read this one image and write this one target, and nowhere else
// the mode would allow. revokeConvert puts both back.
func (r *Runtime) grantConvert(ctx context.Context, img, dst string) error {
	if _, err := r.Host.Run(ctx, "id", ImgUser); err != nil {
		if err := r.run(ctx, "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", ImgUser); err != nil {
			return err
		}
	}
	if err := r.run(ctx, "chgrp", ImgUser, img); err != nil {
		return err
	}
	if err := r.run(ctx, "chmod", "0640", img); err != nil {
		return err
	}
	return r.run(ctx, "chown", ImgUser+":"+ImgUser, dst)
}

func (r *Runtime) revokeConvert(img, dst string) {
	ctx := context.Background()
	_ = r.run(ctx, "chmod", "0600", img)
	_ = r.run(ctx, "chgrp", "root", img)
	_ = r.run(ctx, "chown", "root:root", dst)
}

func (r *Runtime) runConfined(ctx context.Context, img, dst string, argv []string) error {
	args := []string{
		"--wait", "--pipe", "--collect", "--quiet",
		"--unit=kevaso-imgconvert",
		"--property=User=" + ImgUser,
		"--property=Group=" + ImgUser,
		"--property=NoNewPrivileges=yes",
		"--property=CapabilityBoundingSet=",
		"--property=AmbientCapabilities=",
		"--property=ProtectSystem=strict",
		"--property=ProtectHome=yes",
		"--property=PrivateTmp=yes",
		"--property=PrivateDevices=yes",
		"--property=PrivateNetwork=yes",
		"--property=DevicePolicy=closed",
		"--property=ProtectKernelTunables=yes",
		"--property=ProtectKernelModules=yes",
		"--property=ProtectControlGroups=yes",
		"--property=RestrictSUIDSGID=yes",
		"--property=RestrictNamespaces=yes",
		"--property=UMask=0077",
		"--property=TemporaryFileSystem=" + ImagesDir + ":ro",
		"--property=TemporaryFileSystem=/var/lib/kevaso:ro",
		"--property=TemporaryFileSystem=" + SilosDir + ":ro",
		"--property=TemporaryFileSystem=" + ContainersDir + ":ro",
		"--property=BindReadOnlyPaths=" + img,
		"--property=BindPaths=" + dst,
		"--property=InaccessiblePaths=/etc/kevaso /etc/ssh /root",
		"--property=BindsTo=kevasod.service",
		"--property=After=kevasod.service",
	}
	if strings.HasPrefix(dst, "/dev/") {
		args = append(args, "--property=DeviceAllow="+dst+" rw")
	}
	args = append(args, "--", "qemu-img")
	args = append(args, argv...)
	out, err := r.Host.Run(ctx, "systemd-run", args...)
	if err != nil {
		return fmt.Errorf("qemu-img %s: %w: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
