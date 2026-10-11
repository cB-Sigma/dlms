// Test-only module: github.com/cB-Sigma/dlms's client against the Gurux
// DLMS server example in Docker (see interop_test.go). Not part of the
// published module.
module github.com/cB-Sigma/dlms/interop

go 1.25

replace github.com/cB-Sigma/dlms => ../

require (
	github.com/cB-Sigma/dlms v0.0.0
	gitlab.com/circutor-library/gosem v1.3.4
)

require (
	github.com/cB-Sigma/iotsec v0.1.0 // indirect
	github.com/cB-Sigma/schc v0.2.0 // indirect
	github.com/goburrow/serial v0.1.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
