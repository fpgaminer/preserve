How to diff:
	ls -laR --full-time ./ > /tmp/filelist.txt
	cd restored
	ls -laR --full-time ./ > /tmp/filelist-restored.txt

	This will dump out all the permissions, owners, filesize, mtime, etc.  Use diff/vimdiff to compare.
