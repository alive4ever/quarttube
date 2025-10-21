. ~/venv/bin/activate
cd ~/quarttube
if [ -d ./data ] ; then
	rm -f ./data/media_storage.db
	rm -f ./data/cookies.txt
	rm -f ./data/ytcfg.json
fi
if ! [ -f ./data/settings.ini ] ; then
	touch ./data/settings.ini
fi
#watchfiles 'gunicorn --timeout 50 -k uvicorn_worker.UvicornWorker -b localhost:5000 quarttube:app' 'data/settings.ini'
uvicorn --reload --reload-include 'data/settings.ini' --host 'localhost' --port 5000 --no-access-log quarttube:app
