SRC = unfairplay.c
BIN = unfairplay

IOS_HOST := root@ios
TARGET_PATH := /var/jb/bin/$(BIN)

ios:
	clang -arch arm64 \
	      -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) \
	      -miphoneos-version-min=14.0 \
	      $(SRC) -o $(BIN)

ENT = ent.xml

deploy:
	scp -O $(BIN) $(ENT) $(IOS_HOST):/tmp/
	ssh $(IOS_HOST) "mv /tmp/$(BIN) $(TARGET_PATH) && chmod 755 $(TARGET_PATH) && ldid -S/tmp/$(ENT) $(TARGET_PATH)"


# mac:
# 	$(CC) $(SRC) -o $(BIN)
