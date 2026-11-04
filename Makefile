CXX := /home/novusr/Android/Sdk/ndk/android-ndk-r16b/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++
CXXFLAGS := -target aarch64-linux-android -std=c++11 -O3 -ffp-contract=fast -fno-math-errno -fno-strict-aliasing -fno-exceptions -fno-rtti -fPIC -Iinclude

SRCS := $(wildcard src/*.cpp) $(shell find src/units -name '*.cpp' -size +0c 2>/dev/null)
OBJS := $(patsubst src/%.cpp,build/%.o,$(SRCS))

.PHONY: all clean

all: $(OBJS)

build/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf build/units/*.o
