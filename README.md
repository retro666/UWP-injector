# UWP-Injector
> [!CAUTION] 
> WORK IN PROGRESS.
> 
> Currently, we cannot guarantee the stable work of the program.

This program allows you to modify the [Universal Windows Platform Application](https://learn.microsoft.com/windows/uwp/get-started/universal-application-platform-guide) code according to the rules specified in the input file.
# Quick launch
To run the program, use this command:

```
UWP-Injector.exe example.txt
```

Here ```example.txt``` this is a file with the specified injection rules
> [!NOTE] 
> Before performing the injection, you don't need to run the target application, because the injector will do it itself.
# Building a project
To build a project, just type the ```nmake``` command in the Developer Command Prompt.
# Syntax of the rules
There is an example file in the project
> example.txt:
> ```
> Microsoft.WindowsCalculator_8wekyb3d8bbwe!App
> module C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2405.2.0_x64__8wekyb3d8bbwe\CalcViewModel.dll
> replace 8B 41 28 C3 with B8 83 00 00 00 C3
> ```
The first line indicates the UWP App ID.

The second line indicates the full path of the module in which you want to make changes.

The third line specifies the ```replace ... with ...``` rule, which will replace all byte sequence matches with the new ones specified.

After modifying the calculator code, the function that returns the code of the key being pressed will always output the key code 1.
