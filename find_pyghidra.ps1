$ghidraDir = "C:\playground\ghidra_12.0.3_PUBLIC"   # <-- set to your Ghidra install dir
Get-ChildItem (Join-Path $ghidraDir "Ghidra\Features\PyGhidra") -Recurse |
    Where-Object { $_.Name -match '\.whl$|pyghidra|setup\.py|dist-info' } |
    Select-Object FullName
