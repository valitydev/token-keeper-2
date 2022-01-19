# HINT
# Use this file to override variables here.
# For example, to run with podman put `DOCKER=podman` there.
-include Makefile.env

SERVICE := token-keeper

# NOTE
# Variables specified in `.env` file are used to pick and setup specific
# component versions, both when building a development image and when running
# CI workflows on GH Actions. This ensures that tasks run with `wc-` prefix
# (like `wc-dialyze`) are reproducible between local machine and CI runners.
DOTENV := $(shell grep -v '^\#' .env)

DOCKER ?= docker
DOCKERCOMPOSE ?= docker-compose
REBAR ?= rebar3

all: compile

# Development images

DEV_IMAGE_TAG = $(SERVICE)-dev
DEV_IMAGE_ID = $(file < .image.dev)

.PHONY: dev-image clean-dev-image wc-shell test

dev-image: .image.dev

.image.dev: Dockerfile.dev .env
	env $(DOTENV) PLATFORM=$(shell uname -m) DEV_IMAGE_TAG=$(DEV_IMAGE_TAG) $(DOCKERCOMPOSE) build $(SERVICE)-build
	$(DOCKER) image ls -q -f "reference=$(DEV_IMAGE_ID)" | head -n1 > $@

clean-dev-image:
ifneq ($(DEV_IMAGE_ID),)
	$(DOCKER) image rm -f $(DEV_IMAGE_TAG)
	rm .image.dev
endif

DOCKER_WC_OPTIONS := -v $(PWD):$(PWD) --workdir $(PWD)
DOCKER_WC_EXTRA_OPTIONS ?= --rm
DOCKER_RUN = $(DOCKER) run $(DOCKER_WC_OPTIONS) $(DOCKER_WC_EXTRA_OPTIONS)

DOCKERCOMPOSE_RUN = $(DOCKERCOMPOSE) run --name $(SERVICE) $(DOCKER_WC_OPTIONS) $(DOCKER_WC_EXTRA_OPTIONS)

wc-shell: dev-image
	$(DOCKER_RUN) --interactive --tty $(DEV_IMAGE_TAG)

wc-%: dev-image
	$(DOCKER_RUN) $(DEV_IMAGE_TAG) make $*

#  TODO docker compose down doesn't work yet
wdeps-shell: dev-image
	DEV_IMAGE_TAG=$(DEV_IMAGE_TAG) $(DOCKERCOMPOSE) up -d
	DEV_IMAGE_TAG=$(DEV_IMAGE_TAG) $(DOCKERCOMPOSE_RUN) $(SERVICE) su
	DEV_IMAGE_TAG=$(DEV_IMAGE_TAG) $(DOCKERCOMPOSE) down

wdeps-%: dev-image
	{ \
	DEV_IMAGE_TAG=$(DEV_IMAGE_TAG) $(DOCKERCOMPOSE) up -d ; \
	DEV_IMAGE_TAG=$(DEV_IMAGE_TAG) $(DOCKERCOMPOSE_RUN) $(SERVICE)-build make $*  ; \
	res=$$? ; \
	DEV_IMAGE_TAG=$(DEV_IMAGE_TAG) $(DOCKERCOMPOSE) down ; \
	exit $$res ; \
	}

# Erlang-specific tasks

compile:
	$(REBAR) compile

xref:
	$(REBAR) xref

lint:
	$(REBAR) lint

check-format:
	$(REBAR) fmt -c

format:
	$(REBAR) fmt -w

dialyze:
	$(REBAR) as test dialyzer

release:
	$(REBAR) as prod release

clean:
	$(REBAR) clean

distclean: clean-build-image
	rm -rf _build

eunit:
	$(REBAR) eunit --cover

common-test:
	$(REBAR) ct --cover

cover:
	$(REBAR) do cover, covertool generate
