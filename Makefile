DESTDIR:=
prefix:=$(DESTDIR)/opt
REBAR3:=./rebar3
SERVICE:=$(DESTDIR)/etc/systemd/system/mtproto-proxy.service
EPMD_SERVICE:=$(DESTDIR)/etc/systemd/system/epmd.service
LOGDIR:=$(DESTDIR)/var/log/mtproto-proxy
USER:=mtproto-proxy


all: config/prod-sys.config config/prod-vm.args
	$(REBAR3) as prod release

.PHONY: test
test:
	$(REBAR3) xref
	$(REBAR3) eunit -c
	$(REBAR3) ct -c
	$(REBAR3) proper -c -n 50
	$(REBAR3) dialyzer
	$(REBAR3) cover -v

config/prod-sys.config: config/sys.config.example
	[ -f $@ ] && diff $^ $@ || true
	cp -i -b $^ $@
config/prod-vm.args: config/vm.args.example
	[ -f $@ ] && diff $^ $@ || true
	cp -i -b $^ $@
	@IP=$(shell curl -s http://ip.seriyps.ru  || curl -s https://digitalresistance.dog/myIp) \
		&& sed -i s/@0\.0\.0\.0/@$${IP}/ $@

user:
	sudo useradd -r $(USER) || true

$(LOGDIR):
	mkdir -p $(LOGDIR)/
	chown $(USER) $(LOGDIR)/


install: user $(LOGDIR)
	mkdir -p $(prefix)
	cp -r _build/prod/rel/mtp_proxy $(prefix)/
	mkdir -p $(prefix)/mtp_proxy/log/
	chmod 777 $(prefix)/mtp_proxy/log/
	install -D config/mtproto-proxy.service $(SERVICE)
# If there is no "epmd" service, install one
	if [ -z "`systemctl show -p FragmentPath --value epmd`" ]; then \
	    install -D config/epmd.service $(EPMD_SERVICE); \
	fi
	systemctl daemon-reload

uninstall:
# TODO: ensure service is stopped
	rm $(SERVICE)
	rm -r $(prefix)/mtp_proxy/
	systemctl daemon-reload
