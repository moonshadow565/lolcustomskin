#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <array>
#include <cstdio>
#include <cstdlib>
#include "patscanner.hpp"
#include "process.hpp"


namespace ModRemap {
#ifndef __APPLE__
    struct Mutex {
        void* debugInfo;
        long lockCount = - 1;
        long recursionCount;
        void* owningThread;
        void* lockSemaphore;
        uintptr_t spinCount; // & (SIZE_MAX - 1);
    };

    template<typename Signature>
    struct Function {
        void* ptrs[sizeof(void*) == 4 ? 10 : 8];
    };
#else
    struct Mutex {
        int sig;
        char opaq[40];
    };

    template<typename Signature>
    struct Function {
        void* ptrs[6];
    };
#endif

    template<typename T>
    struct Vector {
        T* beg;
        T* end;
        T* cap;
    };
    
    struct AString {
        char* data;
        uint32_t size;
        uint32_t reserved;
    };

    struct StreamVtable {
#ifdef __APPLE__
        void* vectorDeleter;
#endif
        void* base[7];
        void* extra[4];
        void* nullsub2;
    };

    struct Stream {
        void* vtable;
        void* data;
        size_t size;
        size_t pos;
        bool freeData;
    };
    
    struct Chunk {
        uint64_t xxhash;
        uint32_t dataOffset;
        uint32_t sizeCompressed;
        int32_t sizeUncompressed;
        uint8_t type;
        uint8_t isDuplicate;
        uint8_t pad[2];
        uint8_t sha256[8];
    };
    
    struct Redir {
        uint32_t size;
        char name[252];
        Redir() = default;
        constexpr Redir(char const* from) : size{}, name{} {
            for(char* to = name; *from && size++ ; from++, to++) {
                *to = *from;
            }
        }
    };
    
    struct File {
        Mutex mutex; // 0
        Stream* stream; // 24
        Vector<Chunk> chunks; // 28
        AString path; // 40
        void* unkobj; // 52
        Function<void(AString const&, uint64_t)> errorCallback; // 56
    };
    
    struct Manager {
        Mutex mutex;
        Vector<File*> files;
        // void* fileProvider;
        // Map<AString, Vector<IWadFileWatcher>> fileWatchers;
        // UnorderedMap<uint64_t, AString> unkUnordMap;
        // AString extension;
    };
    
    // WadFileManagerPtr mac64(rel ptr)
    // 48 89 08 48 89 43 58 48 89 1D ?? ?? ?? ?? 48 89 C7 48 83 C4 08
    // ConstStreamVtable mac64(rel ptr) in first wildcard(48 8D 05 ....)
    // 55 48 89 E5 48 8D 05 ?? ?? ?? ?? 48 89 07 48 89 77 08 48 89 57 10 48 C7 47 18 00 00 00 00 88 4F 20 5D C3 
    // nullsub2 mac64(offset of function contents)
    // TODO
    
    inline constexpr auto pat_wadmgr = Pattern<
        0x33, 0xC0, 0x89, 0x46, 0x24, 0x89, 0x35, Cap<4>, 0xFF, 0x76, 0x24
    >{};

    inline constexpr auto pat_streamv = Pattern<
        0x8A, 0x44, 0x24, 0x0C, 0x88, 0x41, 0x10, 0x8B, 0xC1, 0xC7, 0x01, Cap<4>
    >{};

    inline constexpr auto pat_nullsub2 = Pattern<
        0xCC, 0xCC, 0xCC, 0xCC, 0xC2, 0x08, 0x00, 0xCC
    >{};
    
    inline constexpr char const schema[] = "lolskinmod-remap v0 0x%08X 0x%08X 0x%08X 0x%08X\n";
    
    struct Config {
        uint32_t checksum = 0;
        uintptr_t off_wadmgr = 0;
        uintptr_t off_streamv = 0;
        uintptr_t off_nullsub2 = 0;

        inline bool good(Process const& process) const noexcept {
            return checksum == process.Checksum() && off_wadmgr && off_streamv && off_nullsub2;
        }

        inline void print() const noexcept {
            printf(schema, checksum, off_wadmgr, off_streamv, off_nullsub2);
        }

        inline void save() const noexcept {
            if(FILE* file = nullptr; !fopen_s(&file, "lolskinmod-test.txt", "w") && file) {
                fprintf_s(file, schema, checksum, off_wadmgr, off_streamv, off_nullsub2);
                fclose(file);
            }
        }

        inline void load() noexcept {
            if(FILE* file = nullptr; !fopen_s(&file, "lolskinmod-test.txt", "r") && file) {
                if(fscanf_s(file, schema, &checksum, &off_wadmgr, &off_streamv, &off_nullsub2) != 4) {
                    checksum = 0;
                    off_wadmgr = 0;
                    off_streamv = 0;
                    off_nullsub2 = 0;
                }
                fclose(file);
            }
        }

        inline bool rescan(Process const& process) noexcept {
            process.WaitWindow("League of Legends (TM) Client", 50);
            auto data = process.Dump();
            auto res_wadmgr = pat_wadmgr(data.data(), data.size());
            auto res_streamv = pat_streamv(data.data(), data.size());
            auto rem_nullsub2 = pat_nullsub2(data.data(), data.size());
            
            if(!res_wadmgr[0] || !res_streamv[0] || !res_streamv[0]) {
                return false;
            }
#ifdef __APPLE__
            off_wadmgr = static_cast<uintptr_t>(res_wadmgr[1] - data.data() + 4)
                        + *reinterpret_cast<uintptr_t const*>(res_wadmgr[1]);
            off_streamv = static_cast<uintptr_t>(res_streamv[1] - data.data() + 4)
                        + *reinterpret_cast<uintptr_t const*>(res_streamv[1]);
#else
            off_wadmgr = process.Debase(*reinterpret_cast<uintptr_t const*>(res_wadmgr[1]));
            off_streamv = process.Debase(*reinterpret_cast<uintptr_t const*>(res_streamv[1]));
            off_nullsub2 = static_cast<uintptr_t>(rem_nullsub2[0] - data.data() + 4);
#endif
            checksum = process.Checksum();
            return true;
        }

        inline void patch(Process const& process) const {
            auto rem_files_arr = process.Allocate<std::array<File*, 512>>();
            auto rem_file = process.Allocate<File>();
            auto rem_stream = process.Allocate<Stream>();
            auto rem_vtable = process.Allocate<StreamVtable>();
            auto rem_chunk = process.Allocate<Chunk>();
            auto rem_redir = process.Allocate<Redir>();

            process.Copy(process.Rebase<StreamVtable>(off_streamv), rem_vtable);
            process.Write(&rem_vtable->nullsub2, process.Rebase(off_nullsub2));
            process.Write(rem_chunk, {
                            .xxhash = 0x199f508a981ce07,
                            .dataOffset = 0,
                            .sizeCompressed = sizeof(Redir),
                            .sizeUncompressed = sizeof(Redir),
                            .type = 2,
                            // .isDuplicate = true,
                            .sha256 = { 0x9E, 0x42, 0xA1, 0xE8, 0x8E, 0xFA, 0x3E, 0xB1 }
                        });
            // process.Write(rem_redir, { "MOD/testme.dds" });
            process.Write(rem_redir, { "assets/characters/ashe/skins/skin03/asheloadscreen_3.dds" });
            process.Write(rem_stream, {
                            .vtable = process.Rebase<void>(off_streamv),
                            .data = rem_redir,
                            .size = sizeof(Redir),
                        });
            process.Write(rem_file, {
                            .stream = rem_stream,
                            .chunks = {
                                .beg = rem_chunk,
                                .end = rem_chunk + 1,
                                .cap = rem_chunk + 1,
                            }
                        });
            process.Write(rem_files_arr->data(), rem_file);

            auto const wadmgr_ptr = process.Rebase<Manager*>(off_wadmgr);
            auto const wadmgr = process.WaitNonZero(wadmgr_ptr);

            /*
            Vector<File*> mod_file_vec = {};
            process.Read(&wadmgr->files, mod_file_vec);
            size_t const org_count = static_cast<size_t>(mod_file_vec.end - mod_file_vec.beg);
            if(org_count) {
                process.Copy(mod_file_vec.beg, rem_files_arr->data() + 1, org_count);
            }
            */

            process.Write(&wadmgr->files, {
                              .beg = rem_files_arr->data(),
                              .end = rem_files_arr->data() + 1,
                              .cap = rem_files_arr->data() + rem_files_arr->size(),
                          });
        }
    };
};
