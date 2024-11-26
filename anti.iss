[Setup]
AppName=Antivirusproject
AppVersion=1.0
DefaultDirName={{pf}}\Antivirusproject
DefaultGroupName=Antivirusproject
OutputDir=dist\installer
OutputBaseFilename=MyAntivirusSetup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin

[Files]
Source: "E:\Arjun\Antivirusproject\dist\run_app.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "E:\Arjun\Antivirusproject\license.txt"; DestDir: "{app}"; Flags: dontcopy

[Icons]
Name: "{group}\Antivirusproject"; Filename: "{app}\run_app.exe"
Name: "{{desktop}}\Antivirusproject"; Filename: "{app}\run_app.exe"; WorkingDir: "{app}"; IconFilename: "{app}\icon.ico"

[Run]
Filename: "{app}\run_app.exe"; Description: "Launch Antivirusproject"; Flags: nowait postinstall skipifsilent

[Code]
var
  SecretKeyPage: TInputQueryWizardPage;

procedure InitializeWizard();
begin
  // Create a custom input page for secret key validation
  SecretKeyPage := CreateInputQueryPage(wpWelcome, 'Secret Key Validation', 
    'Enter your secret key to proceed with the installation', 
    'Please enter your secret key below:');
  SecretKeyPage.Add('Secret Key:', False);

  // Show the license agreement page
  WizardForm.LicensePage.Visible := True;
  WizardForm.LicenseMemo.Lines.LoadFromFile('E:\Arjun\Antivirusproject\license.txt');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  SecretKey: string;
begin
  Result := True; // Default action is to proceed

  // Validate the secret key if on the custom input page
  if CurPageID = SecretKeyPage.ID then
  begin
    SecretKey := SecretKeyPage.Values[0];
    if SecretKey = 'MySecretKey' then  // Replace with your actual secret key logic
    begin
      MsgBox('Secret key validated successfully!', mbInformation, MB_OK);
    end
    else
    begin
      MsgBox('Invalid secret key. Installation will not proceed.', mbError, MB_OK);
      Result := False;  // Prevents proceeding if validation fails
    end;
  end;
end;
