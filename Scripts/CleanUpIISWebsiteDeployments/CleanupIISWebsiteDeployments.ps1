<# 
Written By: Ashley Poole
Date: 21/04/2014
Description: Designed to removed old builds from the web server
#>
param($deleteEnabled='False')

Import-Module WebAdministration -ErrorAction Stop

# Pulling list of websites from IIS
$websites = Get-Website | where {$_.Name -ne "Default Web Site"}

foreach ($website in $websites)
{
	$parentFolderPath = (Get-Item $website.physicalpath).parent.fullname
	$currentFolderName = (Get-Item $website.physicalpath).Name
	
	Write-Host "EVALUATING WEBSITE:" $website.name -ForegroundColor Cyan
	Write-Host "Parent Folder Path:" $parentFolderPath -ForegroundColor Yellow
	Write-Host "Live Folder Name:" $currentFolderName -ForegroundColor Yellow
	
	# Sorting by LastWriteTIme rather than Name due to the same build could be deployed mutiple times caused by a rollback
	$websiteFolders = Get-ChildItem $parentFolderPath | where {$_.Name -ne $currentFolderName} | sort -Property LastWriteTime
	
	$websiteFoldersCount = $websiteFolders.Length -1
	$count = 2
	
	foreach ($folder in $websiteFolders)
	{
		# Only run if we have 3 or more folders lefts
		if ($count -le $websiteFoldersCount)
		{
			# Final check to ensure the folder being deleted isn't the live folder
			if ($folder -ne $website.physicalpath)
			{	
				if ($deleteEnabled -eq 'true')
				{
					Write-Host "DELETEING FOLDER:" $folder
					# Removing folder recursively
					Remove-Item $parentFolderPath\$folder -Force -Recurse
				}
				else
				{
					Write-Host "DELETEING FOLDER (PREVIEW):" $folder
				}
			}
		}
		
		$count++
	}
}