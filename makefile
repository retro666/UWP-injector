all: build clean

build:
	@(FOR /F "tokens=*" %a in ('where cl') do @"%~dpa..\..\..\..\..\..\Auxiliary\Build\vcvars64.bat") & cl /D "UNICODE" UWP-Injector.cpp Ole32.lib

clean:
	@del UWP-injector.obj
