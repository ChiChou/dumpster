SRC = dumpster.m
BIN = dumpster

IOS_HOST := root@ios
TARGET_PATH := /var/jb/bin/$(BIN)

ios:
	clang -arch arm64 -fmodules \
	      -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) \
	      -miphoneos-version-min=14.0 \
	      $(SRC) -o $(BIN)

deploy:
	scp -O $(BIN) $(IOS_HOST):$(TARGET_PATH)
	ssh $(IOS_HOST) "chmod 755 $(TARGET_PATH) && ldid -s/tmp/ent.xml $(TARGET_PATH)"


# mac:
# 	$(CC) $(SRC) -o $(BIN)
