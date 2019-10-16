# jenkinsrole

[![Go Report Card](https://goreportcard.com/badge/github.com/calmandniceperson/jenkinsrole)](https://goreportcard.com/report/github.com/calmandniceperson/jenkinsrole) [![GoDoc](https://godoc.org/github.com/calmandniceperson/jenkinsrole?status.svg)](https://godoc.org/github.com/calmandniceperson/jenkinsrole)

jenkinsrole is a Go package that wraps the API of the Role Strategy plugin for Jenkins. For additional info regarding the plugin itself, see [the plugin page](https://wiki.jenkins.io/display/JENKINS/Role+Strategy+Plugin).

## Using the package

### Installation / import

In order to use the package, run 
```go get github.com/calmandniceperson/jenkinsrole``` and import the package with ```import github.com/calmandniceperson/jenkinsrole```.

### Creating a token

In order to use this package, you need to provide a user token to the Client struct. This token can be acquired by entering the respective user's settings in the top right of the Jenkins UI, selecting `Configure` in the menu on the left side and generating a token in the `API Token` section.

### Creating a client

```go
c := &Client {
    HostName: "http://localhost:8080",
    User: "admin",
    Token: "token123",
}
```

# License

This package is shared under the [MIT License](https://choosealicense.com/licenses/mit/).