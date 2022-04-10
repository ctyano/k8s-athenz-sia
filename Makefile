ifeq ($(GOPATH),)
	GOPATH := $(shell pwd)
endif

export GOPATH

.PHONY: build test

LDFLAGS :=
ifneq ($(ATHENZ_SIA_VERSION),)
LDFLAGS_ARGS += -X main.VERSION=$(ATHENZ_SIA_VERSION)
else
LDFLAGS_ARGS += -X main.VERSION=$(shell grep "github.com/AthenZ/athenz" go.mod | cut -d' ' -f2)
endif
ifneq ($(ATHENZ_SIA_BUILD_DATE),)
LDFLAGS_ARGS += -X main.BUILD_DATE=$(ATHENZ_SIA_BUILD_DATE)
else
LDFLAGS_ARGS += -X main.BUILD_DATE=$(shell date '+%Y-%m-%dT%H:%M:%S')
endif
ifneq ($(ATHENZ_SIA_DEFAULT_COUNTRY),)
LDFLAGS_ARGS += -X identity.DEFAULT_COUNTRY=$(shell echo $$ATHENZ_SIA_DEFAULT_COUNTRY | sed -e 's/\ /\\\ /g')
endif
ifneq ($(ATHENZ_SIA_DEFAULT_PROVINCE),)
LDFLAGS_ARGS += -X identity.DEFAULT_PROVINCE=$(shell echo $$ATHENZ_SIA_DEFAULT_PROVINCE | sed -e 's/\ /\\\ /g')
endif
ifneq ($(ATHENZ_SIA_DEFAULT_ORGANIZATION),)
LDFLAGS_ARGS += -X identity.DEFAULT_ORGANIZATION=$(shell echo $$ATHENZ_SIA_DEFAULT_ORGANIZATION | sed -e 's/\ /\\\ /g')
endif
ifneq ($(ATHENZ_SIA_DEFAULT_ORGANIZATIONAL_UNIT),)
LDFLAGS_ARGS += -X identity.DEFAULT_ORGANIZATIONAL_UNIT=$(shell echo $$ATHENZ_SIA_DEFAULT_ORGANIZATIONAL_UNIT | sed -e 's/\ /\\\ /g')
endif
ifneq ($(ATHENZ_SIA_DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER),)
LDFLAGS_ARGS += -X identity.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER=$(ATHENZ_SIA_DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER)
endif

ifneq ($(LDFLAGS_ARGS),)
LDFLAGS += -ldflags "$(LDFLAGS_ARGS)"
endif

build:
	@echo "Building..."
	go mod tidy
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(GOPATH)/bin/athenz-sia cmd/athenz-sia/*.go

test: build
	@echo "Testing..."
	go test ./...

clean:
	rm -rf $(shell pwd)/bin || true
	chmod -R a+w pkg/ || true
	rm -rf $(shell pwd)/pkg || true
