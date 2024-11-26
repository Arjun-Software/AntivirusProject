[Setup]
AppName=Antivirusproject               ; Name of your application
AppVersion=1.0                       ; Version of your application
DefaultDirName={pf}\Antivirusproject   ; The default directory where the app will be installed
DefaultGroupName=Antivirusproject      ; The name of the program group in the Start Menu
OutputDir=dist\installer             ; The directory where the installer will be created
OutputBaseFilename=MyAntivirusSetup  ; The name of the generated installer file

[Files]
Source: "E:\Arjun\Antivirusproject\dist\run_app.exe"; DestDir: "{app}"; Flags: ignoreversion
; Specifies that the main executable (from the `dist/` folder) will be copied to the {app} directory (the installation directory)

[Icons]
Name: "{group}\Antivirusproject"; Filename: "{app}\run_app.exe"
; Creates a shortcut in the Start Menu with the name "Antivirusproject" that points to the installed executable
