"""
Expanded disposable email detection plugin — includes 500+ disposable email
provider domains. Also checks MX records and domain age as additional signals.
"""
import asyncio
import re
import aiohttp
import dns.resolver
from plugins.base import BasePlugin, PluginResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}

DISPOSABLE_DOMAINS = frozenset({
    # Mailinator family
    "mailinator.com", "mailinator2.com", "notmailinator.com", "mailinater.com",
    "mailinator.net", "mailinator.org", "mailinator.info", "mailinator.biz",
    # Guerrilla Mail family
    "guerrillamail.com", "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "guerrillamail.biz", "guerrillamail.de", "guerrillamail.net", "guerrillamail.org",
    "spam4.me", "sharklasers.com", "guerrillamailblock.com",
    # TempMail / Temp Mail family
    "tempmail.com", "temp-mail.org", "tempmail.io", "temp-mail.io", "tempmailaddress.com",
    "mytemp.email", "tempmail.ninja", "tempmailo.com", "tempmails.com",
    "tempmail.plus", "tempmaily.com", "disposableemailaddresses.emailmiser.com",
    # Throwaway
    "throwaway.email", "throwawaymail.com", "throwam.com", "throwawayemail.com",
    # Yopmail
    "yopmail.com", "yopmail.fr", "yopmail.net", "yopmail.org", "jetable.org",
    "nospam.ze.tc", "nomail.xl.cx", "mail.ciudad.com.ar", "minemail.org",
    # Maildrop
    "maildrop.cc", "maildrop.xyz", "maildrop.technology",
    # Trashmail family
    "trashmail.com", "trashmail.io", "trashmail.me", "trash-mail.org",
    "mytrashmail.com", "trashymail.com", "trashmail.net",
    # Fakeinbox
    "fakeinbox.com", "fakeinbox.co", "fakeinbox.info",
    # Dispostable
    "dispostable.com",
    # Mohmal
    "mohmal.com", "mohmal.io",
    # Minuteinbox
    "minuteinbox.com",
    # 10minutemail
    "10minutemail.com", "10minutemail.net", "10minutemail.org", "10minutemail.info",
    "10minutemailbox.com", "10minutesemail.net", "10minutemailfree.com",
    "10minutemail.net",
    # Tempinbox
    "tempinbox.com",
    # Meltmail
    "meltmail.com",
    # Mailcatch
    "mailcatch.com",
    # Incognitomail
    "incognitomail.org", "incognitomail.net",
    # Filzmail
    "filzmail.com",
    # Mintemail
    "mintemail.com",
    # Spamavert
    "spamavert.com",
    # Tempomail
    "tempomail.fr",
    # Binkmail
    "binkmail.com",
    # Bobmail
    "bobmail.info", "bobmail.org",
    # Chammy
    "chammy.info",
    # Devnullmail
    "devnullmail.com",
    # Digitalsanctuary
    "digitalsanctuary.com",
    # E4ward
    "e4ward.com",
    # Emailigo
    "emailigo.de",
    # Emailtemporario
    "emailtemporario.com.br",
    # Fammix
    "fammix.com",
    # Gishpuppy
    "gishpuppy.com",
    # Guerrillamail (more)
    "gmal.com",
    # Hottempmail
    "hottempmail.com",
    # Inboxkitten
    "inboxkitten.com",
    # Mailcatch
    "mailcatch.com", "mailcatch.io",
    # Mailme
    "mailme.lv", "mailme.moe",
    # Mailnull
    "mailnull.com",
    # Mailsac
    "mailsac.com",
    # Moakt
    "moakt.co", "moakt.com", "moakt.ws",
    # Nada
    "nada.email", "nadamail.com",
    # Neverbox
    "neverbox.com",
    # Nolog
    "nolog.cc",
    # Nsmail
    "nsmail.xyz",
    # Oneoffmail
    "oneoffmail.com",
    # Onetimeemail
    "onetimeemail.com",
    # Proxyemail
    "proxyemail.org",
    # Receiveee
    "receiveee.com",
    # Robomail
    "robomail.me",
    # SAFERSIGNUP
    "safer-signup.de",
    # Safetymail
    "safetymail.info",
    # Spambox
    "spambox.us", "spambox.io",
    # Spamfree24
    "spamfree24.org", "spamfree24.de", "spamfree24.com", "spamfree24.eu", "spamfree24.net",
    # Spammotel
    "spammotel.com",
    # Tempail
    "tempail.com",
    # Tempmailo
    "tempmailo.com",
    # Tempmails
    "tempmails.com",
    # Tmpmail
    "tmpmail.net", "tmpmail.org", "tmpmail.com",
    # Trillian
    "trillian.im",
    # Uemail
    "uemail.me", "uemail.io",
    # Venompen
    "venompen.com",
    # Wayemail
    "wayemail.org",
    # Webemail
    "webemail.me",
    # Wuzup
    "wuzup.net", "wuzupmail.net",
    # Yogamail
    "yogamail.com",
    # Zoho
    "zohomail.com",
    # Getsession
    "session.email",
    # Cryptogmail
    "cryptogmail.com",
    # Tmail
    "tmail.ws", "tmail.gg",
    # Dropmail
    "dropmail.me",
    # Tempmail de
    "tempmail.de",
    # Mailnesia
    "mailnesia.com",
    # Spamgourmet
    "spamgourmet.com", "sg.eat.email",
    # Harakirimail
    "harakirimail.com",
    # Tempmailaddress
    "tempmailaddress.com",
    # Temporarymail
    "temporarymailaddress.com",
    # Emailsensei
    "emailsensei.com",
    # Tempmailnow
    "tempmailnow.com",
    # Oosln
    "oosln.com",
    # Eyepaste
    "eyepaste.com",
    # Mailscrap
    "mailscrap.com",
    # Mailzilla
    "mailzilla.org",
    # Bunoctem
    "bunoctem.com",
    # Datemail
    "datemail.info",
    # Etempmail
    "etempmail.com",
    # Mailbucket
    "mailbucket.org",
    # Nowmymail
    "nowmymail.com",
    # Emailisvalid
    "emailisvalid.com",
    # Smellymail
    "smellymail.com",
    # Tempmailbox
    "tempmailbox.xyz",
    # Tempmail provider
    "tmpmail.net", "tmpmail.org",
    # Disposeamail
    "disposeamail.com",
    # Instantemailaddress
    "instantemailaddress.com",
    # Mailmoat
    "mailmoat.com",
    # Tempmailo
    "tempmailo.org",
    # Mail2world
    "mail2world.com",
    # Tempail
    "tempail.com",
    # Fakeemail
    "fakeemail.com",
    # Throwawaymail
    "throwawaymail.com",
    # Tempmail
    "temp-mail.xyz", "temp-mail.org", "temp-mail.io",
    # Mmmm
    "mmmmail.com",
    # Tempmail
    "tempmailfree.net", "tempmail.email", "tempmail.dev",
    # Generate
    "emailfake.com", "generator.email", "emailfake.org", "emailfake.net",
    # PEC
    "pec.land", "pec.cloud",
    # Dropmail
    "dropmail.gq",
    # Tutanota disposable aliases (note: Tutanota itself is NOT disposable)
    # Sharklasers (Guerrilla)
    "sharklasers.com",
    # Spambog
    "spambog.com", "spambog.de", "spambog.ru",
    # Tempmaildemo
    "tempmaildemo.com",
    # Hsps
    "hps.at", "hsps.xyz",
    # Mail.bccto
    "bccto.me",
    # Mailtest
    "mailtest.in",
    # Trashymail
    "trashymail.com",
    # S0ny
    "s0ny.net",
    # Superrito
    "superrito.com",
    # Tagyourself
    "tagyourself.com",
    # Techemail
    "techemail.com",
    # Thecloud
    "thecloud.net",
    # Throwam
    "throwam.com",
    # Tmail
    "tmpmailr.com",
    # Trollproject
    "trollproject.com",
    # Ubismail
    "ubismail.net",
    # Ugotmail
    "ugotmail.com",
    # Veryrealemail
    "veryrealemail.com",
    # Vipei
    "vipei.com",
    # Webemail24
    "webemail24.com",
    # Wrinkoo
    "wrinkoo.com",
    # Xoxoxma
    "xoxoxma.com",
    # Yopmail
    "yopmail.fr", "yopmail.net", "yopmail.org", "yopmail.com",
    # Yepmail
    "yepmail.us",
    # Yourdomain
    "yourdomain.com",
    # Zeromail
    "zeromail.xyz",
    # Zipzaps
    "zipzap.com",
    # Posteo (not disposable but privacy-focused, skip)
    # Startmail (not disposable, skip)
    # Runbox (not disposable, skip)
    # Internxt (not disposable, skip)
    # Skiff (not disposable, skip)
    # More disposable
    "anonymouse.org", "anonymousemail.me",
    "anonmails.de", "anonymmail.de",
    "antispam.de", "antispammail.de",
    "beefmilk.com",
    "bodhi.lol",
    "buhdomain.com",
    "cleanmail.in", "cleanmail.io",
    "crapmail.org",
    "cuvox.de",
    "daaxs.com", "dacoolest.com",
    "damnthespam.com",
    "dayrep.com",
    "deekayen.us",
    "demenil.com",
    "dfgh.net",
    "digitalsanctuary.com",
    "dingbone.com",
    "discard.email", "discardmail.com", "discardmail.io",
    "donemail.ru",
    "dotmsg.com",
    "drdrb.com", "drdrb.net",
    "easynetwork.info", "easytrashmail.com",
    "ee2.pl",
    "emaildienst.de",
    "emailigo.de",
    "emailsensei.com",
    "emailtemporario.com.br",
    "emeil.in", "emeil.ir",
    "euaaqa.com",
    "evopo.com",
    "fammix.com",
    "faxmail.xyz",
    "fexpost.com",
    "ficks.org",
    "filzmail.com",
    "fixmail.tk",
    "freemail.hu",
    "friendlymail.co.uk",
    "front14.org",
    "fuckingduh.com",
    "gafy.net",
    "galaxy.click",
    "gamesgroove.com",
    "get2mail.fr",
    "getonemail.com", "getonemail.net",
    "ghosttexter.de",
    "gishpuppy.com",
    "girlsundertheinfluence.com",
    "gmal.com",
    "goat.si",
    "godisdead.org",
    "gold-image.org",
    "gotmail.net", "gotmail.org",
    "grandmamail.com", "grandmasmail.com",
    "greathost.in",
    "grr.la",
    "gsxstring.ga",
    "guerillamail.biz", "guerillamail.com", "guerillamail.de",
    "guerillamail.info", "guerillamail.net", "guerillamailblock.com",
    "guerrillamail.biz", "guerrillamail.com", "guerrillamail.de",
    "guerrillamail.info", "guerrillamail.net", "guerrillamailblock.com",
    "guerrillamail.org", "guerrillamailblock.com",
    "haltospam.com",
    "harakirimail.com",
    "hat-geld.de",
    "hatespam.org",
    "heroulo.com",
    "hidemail.de", "hidemail.pro", "hidemail.us",
    "hochsitze.com",
    "hopemail.biz",
    "hotpop.com",
    "hulapla.de",
    "ieatspam.eu", "ieatspam.info",
    "ihateyoualot.info",
    "imails.info",
    "immortals.email",
    "inbax.tk",
    "inboxalias.com", "inboxclean.org", "inboxclean.com",
    "inboxkitten.com",
    "incognitomail.net", "incognitomail.org",
    "instantemailaddress.com",
    "ip6.li",
    "irabod.com",
    "isafreak.com",
    "isksy.com",
    "jmail.ro", "jnxjn.com",
    "jourrapide.com",
    "jp.ftp.sh",
    "kasmail.com",
    "keinhirn.de",
    "killmail.com", "killmail.net",
    "kingsq.ga",
    "klassmaster.com", "klassmaster.net",
    "kook.ml",
    "kostenlosemailadresse.de",
    "kurzepost.de",
    "l33r.eu",
    "lackmail.net", "lackmail.ru",
    "laoeq.com",
    "lastmail.co", "lastmail.com",
    "lawlita.com",
    "lazyinbox.com",
    "letthemeatspam.com",
    "lifebyfood.com",
    "link2mail.net",
    "linuxmail.so",
    "litedrop.com",
    "loadby.us",
    "login-email.ml",
    "lol.ovpn.to",
    "lopl.co.cc",
    "lortemail.dk",
    "lovemeleaveme.com",
    "lr78.com",
    "luckymail.org",
    "mac.hush.com",
    "mabox.eu",
    "mail-filter.com",
    "mail.mezimages.net", "mail1a.de",
    "mailblocks.com",
    "mailbucket.org",
    "mailcat.biz",
    "mailcatch.com",
    "mailde.de",
    "maildrop.cc", "maildrop.technology", "maildrop.xyz",
    "maileater.com",
    "mailexpire.com",
    "mailforspam.com",
    "mailfreeonline.com",
    "mailguard.me",
    "mailhazard.com",
    "mailimate.com",
    "mailinater.com",
    "mailinator.com", "mailinator.net",
    "mailjunk.com", "mailjunk.net",
    "mailme.lv",
    "mailmoat.com",
    "mailnull.com",
    "mailpick.biz",
    "mailsac.com",
    "mailscrap.com",
    "mailshell.com",
    "mailzilla.org",
    "mattz.eu",
    "meinspamschutz.de",
    "menzel.cc",
    "mertens.nu",
    "messagebeamer.de",
    "mezimages.net",
    "migumail.com",
    "ministry-of-silly-walks.de",
    "misterpinball.de",
    "mjaouen.com",
    "moakt.co", "moakt.com", "moakt.ws",
    "moburl.com",
    "monumentmail.com",
    "msa.minsmail.com",
    "mt2015.com",
    "muchomail.com",
    "mwarner.org",
    "mx0.wwwnew.eu",
    "mycleaninbox.net",
    "myemailboxy.com",
    "myopang.com",
    "mymail-in.net",
    "mytemp.email", "mytempemail.com",
    "neomailbox.com",
    "nervmich.net",
    "netmails.com", "netmails.net",
    "neverbox.com",
    "nobugmail.com",
    "noclickemail.com",
    "nogmailspam.info",
    "nomail.xl.cx",
    "nomail2me.com",
    "nomorespamemails.com",
    "nospam.ze.tc",
    "nospam4.us", "nospamfor.us",
    "nospammail.us",
    "notmailinator.com", "notrnailinator.com",
    "nowhere.org",
    "nowmymail.com",
    "nube.mx",
    "objectmail.com",
    "obobbo.com",
    "odaymail.com",
    "offshorepitbulls.com",
    "ohaa.de",
    "okzk.com",
    "oneoffemail.com",
    "onewaymail.com",
    "online.ms",
    "oopi.org",
    "ourklips.com",
    "outlawspam.com",
    "owlpic.com",
    "pancakemail.com",
    "paplease.com",
    "pepbot.com",
    "pimpedupmyspace.com",
    "pjjkp.com",
    "plexolan.de",
    "polymail.in",
    "pooae.com",
    "popmailserv.org",
    "postonline.me",
    "privacy.net",
    "privy-mail.com", "privymail.de",
    "proxymail.eu", "proxyemail.org",
    "prtz.eu",
    "punkass.com",
    "putthisinyourspamdatabase.com",
    "pwrby.com",
    "qasti.com",
    "qisdo.com",
    "qoto.org",
    "quickemail.info",
    "quickinbox.com",
    "rcpt.at",
    "reallymymail.com",
    "realtyalerts.ca",
    "receiveee.com",
    "recode.me",
    "recursor.net",
    "regbypass.com",
    "remail.cf",
    "remail.ga",
    "rhyta.com",
    "rklips.com",
    "rmqkr.net",
    "royal.net",
    "ruffrey.com",
    "s0ny.net",
    "safersignup.de",
    "safetymail.info",
    "safersignup.de",
    "safetypost.de",
    "saynotospams.com",
    "scbox.one",
    "schrott-email.de",
    "secretemail.de",
    "secure-mail.biz",
    "sendspamhere.com",
    "services.cx",
    "sharklasers.com",
    "shieldemail.com",
    "shiftmail.com",
    "shipfromto.com",
    "shitmail.de", "shitmail.org", "shitmail.me", "shitmail.pl",
    "shortmail.net",
    "sify.com",
    "singlespruce.com",
    "sinnlos-mail.de",
    "slapsfromlastnight.com",
    "slaskpost.se",
    "slopsbox.com",
    "smashmail.de",
    "smellfear.com",
    "snakemail.com",
    "sneakemail.com",
    "socialfury.com",
    "softpls.com",
    "softhome.net",
    "sogetthis.com",
    "solidscribe.com",
    "spamavert.com",
    "spambob.com", "spambob.net", "spambob.org",
    "spambox.us", "spambox.io",
    "spamcannon.com", "spamcannon.net",
    "spamcon.org",
    "spamcorptastic.com",
    "spamday.com", "spamdecoy.net",
    "spamex.com",
    "spamfree24.com", "spamfree24.de", "spamfree24.eu",
    "spamfree24.net", "spamfree24.org",
    "spamgourmet.com", "spamherelots.com",
    "spamhole.com",
    "spamify.com",
    "spaminator.de",
    "spamlot.com",
    "spammotel.com",
    "spamobox.com",
    "spamsalad.in",
    "spamsphere.com",
    "spamstack.net",
    "spamthis.co.uk", "spamthisplease.com",
    "spamtrail.com",
    "spamtroll.net",
    "speed.1s.fr",
    "spikio.com",
    "spoofmail.de",
    "squizzy.de",
    "squeezemail.com",
    "ssedr.com",
    "startmail.com",
    "steambot.net",
    "stop-my-spam.com",
    "streetwisemail.com",
    "stuffmail.de",
    "super-auswahl.de",
    "superplatyna.com",
    "suremail.info",
    "svk.jp",
    "sylvanduck.com",
    "t.psh.me",
    "tagyourself.com",
    "talkinator.com",
    "techie.com",
    "teewars.org",
    "teleworm.com",
    "tempail.com", "tempail.co",
    "tempb.in",
    "tempemail.co.za", "tempemail.com", "tempemail.net",
    "tempemailaddress.com", "tempemailo.com",
    "tempinbox.com", "tempinbox.co.uk",
    "tempmail.com", "tempmail.de", "tempmail.eu",
    "tempmail.io", "tempmail.ninja", "tempmail.plus",
    "tempmailaddress.com", "tempmailbox.xyz", "tempmailo.com",
    "tempmailo.org", "tempmails.com", "tempmaily.com",
    "tempomail.fr",
    "temporaryemailaddress.com",
    "temporarymailaddress.com", "temporaryforwarding.com",
    "tempthe.net",
    "thanksnospam.info",
    "thc.st", "thecloud.com", "thecloud.de", "thecloud.net",
    "thelimestones.com",
    "thisisnotmyrealemail.com",
    "thismail.net",
    "throwawayemailaddress.com",
    "throwawaymail.com",
    "tilien.com",
    "tittbit.in",
    "tmail.ws", "tmail.gg",
    "tmpbox.net",
    "tmpjr.me",
    "tmpmail.net", "tmpmail.org", "tmpmailr.com",
    "toomail.biz",
    "topinmail.com",
    "trash2009.com",
    "trashamil.com",
    "trashemail.de", "trashmail.com", "trashmail.io", "trashmail.me",
    "trashmail.net", "trashmail.org", "trashmail.ws",
    "trickmail.net",
    "trillian.im",
    "tryninja.io",
    "tso.net",
    "turbomail.org",
    "turbopizza.net",
    "twocowmail.net",
    "ubismail.net",
    "ugotmail.com",
    "uhhu.ru",
    "umail.net",
    "unmail.ru",
    "upliftnow.com",
    "uplipht.com",
    "us.af", "users.skynet.be",
    "vaulter.email",
    "venompen.com",
    "veryrealemail.com",
    "vidchart.com",
    "viewcastmedia.com",
    "viralplays.com",
    "vipei.com",
    "vipmail.name",
    "vztc.com",
    "wasteland.rfc822.org",
    "webemail24.com",
    "webuser.in",
    "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
    "wh4f.org",
    "whyspam.me",
    "willselfdestruct.com",
    "wimsg.com",
    "winemaven.info",
    "wuzup.net", "wuzupmail.net",
    "www.e4ward.com", "www.gishpuppy.com", "www.mailcatch.com",
    "wwwnew.eu",
    "xagloo.co", "xagloo.com",
    "xmaily.com",
    "xoxoxma.com",
    "yopmail.com", "yopmail.fr", "yopmail.net",
    "ypmail.webarnak.fr.eu.org",
    "yuurok.com",
    "z1p.biz",
    "zehnminutenmail.de",
    "zippymail.info", "zipzap.com",
    "zoemail.com", "zoemail.net", "zoemail.org",
    "zomg.info",
    "zzz.com",
})


class EmailDisposablePlugin(BasePlugin):
    name = "email_disposable"
    description = "Expanded disposable email detection with 500+ domains, MX and age checks"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        if not EMAIL_RE.match(target):
            return PluginResult(plugin_name=self.name, success=False, error="Not a valid email address")

        local, domain = target.lower().rsplit("@", 1)

        # Primary check: hardcoded list
        is_disposable = domain in DISPOSABLE_DOMAINS

        # Secondary signals
        mx_signal = False
        age_signal = False
        mx_records = []
        domain_age_days = None

        async def check_mx():
            nonlocal mx_signal, mx_records
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "MX")
                )
                mx_records = [str(r.exchange).rstrip(".") for r in answers]
                # If no MX records despite being in the list, that's suspicious too
                # Some disposable providers DO have MX
            except Exception:
                # No MX at all — additional disposable signal
                mx_signal = True

        async def check_domain_age():
            nonlocal age_signal, domain_age_days
            if is_disposable:
                return
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    url = f"https://rdap.org/domain/{domain}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            events = data.get("events", [])
                            for ev in events:
                                if ev.get("eventAction") == "registration":
                                    date_str = ev.get("eventDate")
                                    if date_str:
                                        from datetime import datetime, timezone
                                        try:
                                            created = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                                            now = datetime.now(timezone.utc)
                                            delta = now - created
                                            domain_age_days = delta.days
                                            if delta.days < 30:
                                                age_signal = True
                                        except Exception:
                                            pass
                                    break
            except Exception:
                pass

        await asyncio.gather(check_mx(), check_domain_age())

        # Combined assessment
        signals = []
        if is_disposable:
            signals.append({"signal": "domain_in_disposable_list", "value": True})
        if mx_signal:
            signals.append({"signal": "no_mx_records", "value": True})
        if age_signal:
            signals.append({"signal": "domain_age_under_30_days", "value": True, "age_days": domain_age_days})

        # Final determination
        final_disposable = is_disposable or (mx_signal and age_signal)
        confidence = "high"
        if not is_disposable and final_disposable:
            confidence = "medium"
        elif is_disposable:
            confidence = "high"

        risk_flags = []
        if final_disposable:
            if is_disposable:
                risk_flags.append(f"🗑️ Disposable email provider: {domain}")
            elif mx_signal and age_signal:
                risk_flags.append(f"⚠️ Likely disposable: no MX + domain age {domain_age_days} days")

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "email": target,
                "domain": domain,
                "disposable": final_disposable,
                "confidence": confidence,
                "in_disposable_list": is_disposable,
                "list_size": len(DISPOSABLE_DOMAINS),
                "mx_records": mx_records,
                "no_mx": mx_signal,
                "domain_age_days": domain_age_days,
                "domain_age_signal": age_signal,
                "signals": signals,
                "risk_flags": risk_flags,
            },
        )