#!/bin/sh
# Makes this Mac reachable by kvoadm for the Mac-worker end-to-end test, and undoes it.
#
#   sh test/e2e/mac-setup.sh setup       Remote Login on, a test SSH key authorized for you, passwordless sudo for you
#   sh test/e2e/mac-setup.sh teardown    all three removed (Remote Login back to how it was)
#
# These are security settings, so you run it, not a session; it asks for your password once (sudo).
# kvoadm logs in over SSH and runs every change with `sudo -n`, which is why sudo must not ask.
set -eu
key="$HOME/.ssh/kevaso-mac-test"
sudoers=/etc/sudoers.d/kevaso-mac-test
mark="$HOME/.kevaso-mac-test-remote-login"
tag="kevaso-mac-test"

case "${1:-}" in
setup)
	sudo -v
	if [ ! -f "$key" ]; then ssh-keygen -q -t ed25519 -N "" -C "$tag" -f "$key"; fi
	mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; touch "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"
	grep -q " $tag\$" "$HOME/.ssh/authorized_keys" || cat "$key.pub" >> "$HOME/.ssh/authorized_keys"
	printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$(id -un)" | sudo tee "$sudoers" >/dev/null
	sudo chmod 440 "$sudoers"; sudo visudo -c -f "$sudoers" >/dev/null
	if sudo systemsetup -getremotelogin 2>/dev/null | grep -qi "on"; then echo was-on > "$mark"; else echo was-off > "$mark"; fi
	sudo systemsetup -setremotelogin on
	echo "ready: ssh -i $key -o StrictHostKeyChecking=accept-new $(id -un)@127.0.0.1 true"
	;;
teardown)
	sudo -v
	sudo rm -f "$sudoers"
	if [ -f "$HOME/.ssh/authorized_keys" ]; then grep -v " $tag\$" "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/authorized_keys.new" || true; mv "$HOME/.ssh/authorized_keys.new" "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"; fi
	rm -f "$key" "$key.pub"
	if [ -f "$mark" ] && grep -q was-off "$mark"; then sudo systemsetup -setremotelogin off; fi
	rm -f "$mark"
	echo "undone"
	;;
*)
	echo "usage: sh test/e2e/mac-setup.sh setup|teardown" >&2; exit 2 ;;
esac
