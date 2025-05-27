# Windows Admin Toolkit – IT390R

## Added Tasks

### `--task win-tasks`
Lists non-Microsoft scheduled tasks with next run time and command.  
AI citation: Copilot snippet (parsed schtasks CSV)

### `--task win-startup`
Lists startup programs from Windows registry for current user.  
AI citation: ChatGPT snippet (query startup registry)

## Example Runs

```powershell
python analyze_windows.py --task win-tasks
python analyze_windows.py --task win-startup
