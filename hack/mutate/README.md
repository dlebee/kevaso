# Mutation check of the safety guards

A guard is a check whose removal would let a silo start twice, data be deleted without a delete, a
port open that was not opened, a secret reach a place it should not, or a destructive command run
on the wrong target. `mutations.json` lists the ones that matter most: for each, the file, the
exact text to change, what it becomes (the check deleted, inverted or made to always pass), and
the packages whose tests must notice.

```bash
make mutate                          # every mutation, three at a time: about an hour. Nightly in CI.
go run ./hack/mutate -id G-001,G-014 # some of them
go run ./hack/mutate -id G-001 -run TestAMoveTo -pkgs ./internal/agent   # check one new test fast
```

It never touches the working tree: the mutated file goes to a temporary directory and
`go test -overlay` reads it from there. Each mutation prints `killed` (a test failed: the name is
shown), `SURVIVED` (every test passed with the guard gone: write a test, in a new file, that
fails under this mutation and passes on the real code) or `invalid` (the text no longer matches:
the code moved; fix the entry). The exit status is 1 unless everything was killed.

Adding a guard: add an entry to `mutations.json` (`find` must occur exactly once in `file`), run
it, and write the test if it survives. A mutation that makes the package panic or time out is
counted as killed ("package-level"); look at it by hand, since a timeout is a slow way to be killed.
