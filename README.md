# UDACITY Full Stack Nanodegree  
# Unit 4: Catalog App 

Configuration Instructions:
1. Make sure both Vagrant and VirtualBox are installed. 
2. Install the latest version of Python 2  
3. Install the following modules:  
- sqlalchemy, flask, oauth2client, functools

Instructions to run:  
 
1. Download the files in this repository and save to a directory.  
2. Open a terminal and activate the virtual machine with 'vagrant up'  
3. Log into the virtual machine with 'vagrant ssh'  
4. Navigate to vagrant/catalog.  
5. Run the script: 'python application.py'  

Operating Instructions:  
To access the API endpoints, you must be logged in.  
1. Get a list of all Playlists:
	'/playlist/JSON'
2. Get info for a specific Playlist:  
	'/playlist/{playlist_id}/track/JSON'
3. Get info for a specific Track:
	'/playlist/{playlist_id}/track/{track_id}/JSON'