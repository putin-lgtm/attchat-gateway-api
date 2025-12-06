@echo off
echo Checking if Air is installed...
where air >nul 2>&1
if %errorlevel% neq 0 (
    echo Air not found. Installing...
    go install github.com/air-verse/air@latest
    echo Done! Make sure %GOPATH%\bin is in your PATH
) else (
    echo Air is already installed.
)

echo.
echo Checking if Swag is installed...
where swag >nul 2>&1
if %errorlevel% neq 0 (
    echo Swag not found. Installing...
    go install github.com/swaggo/swag/cmd/swag@latest
    echo Done!
) else (
    echo Swag is already installed.
)

echo.
echo Starting development server with live reload...
echo Swagger docs will auto-regenerate on file changes.
air
