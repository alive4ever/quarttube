. ~/venv/bin/activate
cd ~/quarttube
if [ -d ./data ] ; then
	rm -f ./data/media_storage.json
	rm -f ./data/cookies.txt
	rm -f ./data/ytcfg.json
fi
#gunicorn --reload-extra-file 'data/settings.ini' --reload --timeout 50 -k uvicorn_worker.UvicornWorker -b localhost:5000 quarttube:app
uvicorn --reload --reload-include 'data/settings.ini' --host 'localhost' --port 5000 --no-access-log quarttube:app
