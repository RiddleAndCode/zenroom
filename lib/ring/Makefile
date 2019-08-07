NAME := zenroom_ring
ARCHIVE := lib$(NAME).a

LIB := target/lib
INCLUDE := target/include

default: usage

.PHONY: build
build:
	mkdir -p $(LIB)
	mkdir -p $(INCLUDE)
	cargo build --release --target $(TARGET)
	cp -rf target/$(TARGET)/release/$(ARCHIVE) $(LIB)/$(ARCHIVE)

.PHONY: clean
clean:
	cargo clean

.PHONY: clean
usage:
	@echo "[environment] make [command]"
	@echo ""
	@echo "  commands"
	@echo "    build - build the static libs"
	@echo "            output in target/lib"
	@echo "    clean - remove built targets"
	@echo ""
	@echo "  environment"
	@echo "    TARGET = rust triplet"
