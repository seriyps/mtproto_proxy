DESTDIR:=/opt
REBAR3:=./rebar3
SERVICE:=/etc/systemd/system/mtproto-proxy.service
LOGDIR:=/var/log/mtproto-proxy
USER:=mtproto-proxy


all: config/prod-sys.config config/prod-vm.args
	$(REBAR3) as prod release

config/prod-sys.config: config/sys.config.example
	[ -f $@ ] && diff $^ $@ || true
	cp -i -b $^ $@
config/prod-vm.args: config/vm.args.example
	[ -f $@ ] && diff $^ $@ || true
	cp -i -b $^ $@

$(LOGDIR):
	mkdir -p $(LOGDIR)
	chown $(USER) $(LOGDIR)


install: $(LOGDIR)
	sudo useradd -r $(USER) || true
	cp -n -r _build/prod/rel/mtp_proxy $(DESTDIR)
	mkdir -p $(DESTDIR)/mtp_proxy/log
	chmod 777 $(DESTDIR)/mtp_proxy/log
	cp -n config/mtproto-proxy.service $(SERVICE)
	systemctl daemon-reload

uninstall:
# TODO: ensure service is stopped
	rm $(SERVICE)
	rm -r $(DESTDIR)/mtp_proxy
	systemctl daemon-reload
