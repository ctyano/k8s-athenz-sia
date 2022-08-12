# k8s-athenz-sia

## Usage

```
$GOPATH/bin/athenz-sia --help
```

## Build

### To update the git submodule from the latest commit (HEAD) hash of the remote repository

```
git submodule update --recursive --init --remote
make
```

### To update the git submodule from the remote repository

```
git submodule update --recursive --init
make
```
