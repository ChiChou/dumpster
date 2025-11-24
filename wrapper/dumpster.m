#include <mach-o/loader.h>
#import <Foundation/Foundation.h>
#include <sys/stat.h>

@interface LSApplicationProxy
@property (nonatomic, readonly) NSString *teamID;
@property (nonatomic, readonly) NSString* bundleIdentifier;
@property (nonatomic, readonly) NSString* applicationIdentifier;
@property (nonatomic, readonly) NSURL* bundleURL;

+ (id)applicationProxyForIdentifier:(id)bundle;
@end

int is_encrypted_macho(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return 0;
  }

  struct stat s;
  if (fstat(fd, &s) < 0) {
    goto cleanup;
  }

  // mmap
  void *mapped = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mapped == MAP_FAILED) {
    goto cleanup;
  }

  struct mach_header_64 *header = (struct mach_header_64 *)mapped;
  if (header->magic != MH_MAGIC_64 || header->cputype != CPU_TYPE_ARM64) {
    goto unmap;
  }

  uint32_t offset = sizeof(struct mach_header_64);
  for (uint32_t i = 0; i < header->ncmds; i++) {
    struct load_command *cmd = (struct load_command *)(mapped + offset);
    if (cmd->cmd == LC_ENCRYPTION_INFO_64) {
      struct encryption_info_command_64 *enc_cmd = (struct encryption_info_command_64 *)cmd;
      if (enc_cmd->cryptid != 0) {
        munmap(mapped, s.st_size);
        close(fd);
        return 1;
      } else {
        break;
      }
    }
    offset += cmd->cmdsize;
  }

unmap:
  munmap(mapped, s.st_size);

cleanup:
  close(fd);
  return 0;

}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    [[NSBundle bundleWithPath:@"/System/Library/Frameworks/CoreServices.framework"] load];

    if (argc < 2) {
      NSLog(@"Usage: %s <bundle_identifier> <output>", argv[0]);
      return 1;
    }

    NSString *bundleIdentifier = [NSString stringWithUTF8String:argv[1]];
    LSApplicationProxy *appProxy = [NSClassFromString(@"LSApplicationProxy") applicationProxyForIdentifier:bundleIdentifier];

    if (appProxy && appProxy.bundleURL) {
      unsigned long prefix_len = strlen(appProxy.bundleURL.path.UTF8String);
      puts(appProxy.bundleURL.path.UTF8String);

      NSFileManager *fileManager = [NSFileManager defaultManager];
      NSDirectoryEnumerator *enumerator = [fileManager enumeratorAtURL:appProxy.bundleURL
                                            includingPropertiesForKeys:nil
                                                               options:0
                                                          errorHandler:nil];
      NSMutableArray<NSString *> *filePaths = [NSMutableArray array];
      for (NSURL *fileURL in enumerator) {
        const char *path = fileURL.path.UTF8String;
        if (is_encrypted_macho(path)) {
          puts(path + prefix_len + 1);
        }
      }
    } else {
      NSLog(@"No application found for bundle identifier: %@", bundleIdentifier);
      return 1;
    }
  }
  return 0;
}
