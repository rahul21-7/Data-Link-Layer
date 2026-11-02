@echo off
echo ========================================================
echo Building Data Link Layer C++ Simulator
echo ========================================================

if not exist bin mkdir bin
if not exist captures mkdir captures

g++ -std=c++14 -O2 -Iinclude src\main.cpp src\Crc.cpp src\Frame.cpp src\Channel.cpp src\GbnSender.cpp src\GbnReceiver.cpp src\CsmaNode.cpp src\PcapWriter.cpp -lws2_32 -o bin\dll_simulator.exe

if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Built bin\dll_simulator.exe successfully!
    echo To run: bin\dll_simulator.exe
) else (
    echo.
    echo [ERROR] Compilation failed.
)
