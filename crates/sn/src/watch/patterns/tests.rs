//! Each rule against the legitimate traffic it used to ban, and against the
//! attack it must still catch.

use super::*;
use snsec_common::logfmt::{LogFormat, parse_line};

const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0) Chrome/148.0.0.0 Safari/537.36";
const IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 Version/18.5 Mobile/15E148 Safari/604.1";
const GOOGLEBOT: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

fn line_from(ip: &str, method: &str, path: &str, status: u16, ua: &str) -> LogLine {
    let l = format!(r#"{ip} - - [x] "{method} {path} HTTP/1.1" {status} 1 "-" "{ua}""#);
    parse_line(LogFormat::Combined, &l, &[]).unwrap()
}

fn line(s: &str) -> LogLine {
    parse_line(LogFormat::Combined, s, &[]).unwrap()
}

/// `times` identical requests from 1.2.3.4 to `site`.
fn send(a: &mut IpAgg, site: u64, method: &str, path: &str, status: u16, ua: &str, times: usize) {
    let l = line_from("1.2.3.4", method, path, status, ua);
    for _ in 0..times {
        a.observe(&l, site);
    }
}

fn get(a: &mut IpAgg, path: &str, status: u16, ua: &str) {
    send(a, 0, "GET", path, status, ua, 1);
}

/// A server whose baseline has learned its traffic, with the default floor.
fn ready() -> Judge {
    Judge {
        threshold: 300,
        baseline_ready: true,
        ceiling: 3000,
        volume: true,
        crawler: false,
    }
}

/// One page view: the HTML, its CSS/JS, images and fonts, and the WooCommerce
/// cart fragments call. About 65 lines, three of them dynamic.
fn page_view(a: &mut IpAgg, site: u64, ua: &str, page: &str) {
    send(a, site, "GET", page, 200, ua, 1);
    for i in 0..30 {
        send(
            a,
            site,
            "GET",
            &format!("/wp-content/plugins/p{i}/x.js?ver=6.5"),
            200,
            ua,
            1,
        );
    }
    for i in 0..25 {
        send(
            a,
            site,
            "GET",
            &format!("/wp-content/uploads/2026/05/sp-{i}-300x300.webp"),
            200,
            ua,
            1,
        );
    }
    send(
        a,
        site,
        "GET",
        "/wp-content/themes/t/fonts/a.woff2",
        200,
        ua,
        4,
    );
    send(a, site, "GET", "/wp-content/themes/t/style.css", 304, ua, 4);
    send(
        a,
        site,
        "POST",
        "/?wc-ajax=get_refreshed_fragments",
        200,
        ua,
        1,
    );
    send(a, site, "GET", "/wp-json/wc/store/v1/cart", 200, ua, 1);
}

// ---- rate: dynamic requests, per site, per client ---------------------------

#[test]
fn a_shopper_browsing_a_store_is_far_from_the_rate_bar() {
    // Home page and a 36-product category with thumbnails: ~155 lines used to
    // pass the old bar of 120 lines; only 6 are dynamic.
    let mut a = IpAgg::default();
    page_view(&mut a, 1, BROWSER, "/");
    page_view(&mut a, 1, BROWSER, "/danh-muc/ao-thun/");
    send(
        &mut a,
        1,
        "GET",
        "/wp-content/uploads/2026/05/thumb.jpg",
        200,
        BROWSER,
        40,
    );
    assert!(a.requests > 150, "{}", a.requests);
    assert_eq!(a.dynamic(), 6);
    assert!(judge(&a, &ready()).is_none());
    // A video watched in range requests, and a gallery of 150 thumbnails.
    let mut a = IpAgg::default();
    send(
        &mut a,
        1,
        "GET",
        "/wp-content/uploads/clip.mp4",
        206,
        BROWSER,
        120,
    );
    send(&mut a, 1, "GET", "/gallery/", 200, BROWSER, 1);
    send(
        &mut a,
        1,
        "GET",
        "/wp-content/uploads/g.jpg",
        200,
        BROWSER,
        150,
    );
    assert_eq!(a.dynamic(), 1);
    assert!(judge(&a, &ready()).is_none());
}

#[test]
fn a_206_or_304_answer_and_a_page_asset_are_not_dynamic_but_a_sitemap_is() {
    let mut a = IpAgg::default();
    get(&mut a, "/app.js", 200, BROWSER);
    get(&mut a, "/page/", 304, BROWSER);
    get(&mut a, "/video.webm", 206, BROWSER);
    get(&mut a, "/font.WOFF2?v=3", 200, BROWSER);
    assert_eq!(a.dynamic(), 0);
    get(&mut a, "/sitemap_index.xml", 200, BROWSER);
    get(&mut a, "/wp-admin/admin-ajax.php", 200, BROWSER);
    get(&mut a, "/backup.zip", 404, BROWSER);
    assert_eq!(a.dynamic(), 3);
    for p in ["/a.css", "/x/y.PNG", "/f.woff2", "/v.mp4", "/s.js.map"] {
        assert!(is_asset(p), "{p}");
    }
    for p in [
        "/",
        "/sitemap.xml",
        "/readme.txt",
        "/db.sql",
        "/index.php",
        "/a.css/",
    ] {
        assert!(!is_asset(p), "{p}");
    }
}

#[test]
fn an_l7_flood_is_banned_and_climbs_the_ladder() {
    // Search abuse from one tool at 3-4 requests a second.
    let mut a = IpAgg::default();
    for i in 0..1000 {
        send(
            &mut a,
            1,
            "GET",
            &format!("/?s=q{i}"),
            200,
            "python-requests/2.31",
            1,
        );
    }
    let h = judge(&a, &ready()).unwrap();
    assert_eq!(
        (h.reason, h.ban, h.escalate, h.ttl_cap),
        ("rate", true, true, 0)
    );
    // The same from a browser User-Agent still bans, at most an hour per strike.
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/wp-login.php", 200, BROWSER, 900);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ban, h.escalate), ("rate", true, true));
    assert_eq!(h.ttl_cap, 3600);
}

#[test]
fn a_flood_of_static_files_still_hits_the_total_ceiling() {
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/logo.png", 200, "curl/8.5", 3000);
    assert_eq!(a.dynamic(), 0);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ban), ("rate", true));
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/logo.png", 200, "curl/8.5", 2999);
    assert!(judge(&a, &ready()).is_none());
}

#[test]
fn a_carrier_nat_with_several_browsers_gets_a_higher_bar_and_a_short_ban() {
    // Three people on one 4G address browsing the same shop.
    let mut a = IpAgg::default();
    for ua in [
        BROWSER,
        IPHONE,
        "Mozilla/5.0 (Linux; Android 15) Chrome/147.0 Mobile Safari/537.36",
    ] {
        send(&mut a, 1, "GET", "/san-pham/", 200, ua, 250);
    }
    assert_eq!(a.clients(), 3);
    assert_eq!(a.site_dynamic(), 750);
    assert!(judge(&a, &ready()).is_none(), "750 < 3 x 300");
    // Very busy: banned, but briefly and never up the ladder.
    send(&mut a, 1, "GET", "/san-pham/", 200, BROWSER, 200);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!(
        (h.reason, h.ban, h.escalate, h.ttl_secs),
        ("rate", true, false, 600)
    );
}

#[test]
fn rotating_user_agents_gains_at_most_four_times_the_bar() {
    let mut a = IpAgg::default();
    for i in 0..400 {
        let ua = format!("Mozilla/5.0 (Windows NT 10.0) Chrome/{i}.0 Safari/537.36");
        send(&mut a, 1, "GET", &format!("/?p={i}"), 200, &ua, 3);
    }
    assert_eq!(a.clients(), MAX_CLIENTS);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ban), ("rate", true), "1200 >= 4 x 300");
}

#[test]
fn many_sites_on_one_vps_are_judged_one_by_one_with_a_backstop() {
    // An uptime monitor or a MainWP dashboard: 40 sites, 5 requests each.
    let mut a = IpAgg::default();
    for site in 0..40 {
        send(&mut a, site, "GET", "/wp-cron.php", 200, "MainWP/5.0", 5);
    }
    assert_eq!(a.dynamic(), 200);
    assert!(judge(&a, &ready()).is_none());
    // An agency office working on 20 client sites, 40 pages each.
    let mut a = IpAgg::default();
    for site in 0..20 {
        send(&mut a, site, "GET", "/wp-admin/post.php", 200, BROWSER, 40);
    }
    assert!(judge(&a, &ready()).is_none(), "800 over 20 sites");
    // A flood sprayed over every site still adds up past the backstop.
    let mut a = IpAgg::default();
    for site in 0..40 {
        send(&mut a, site, "GET", "/?s=x", 200, "curl/8.5", 25);
    }
    assert_eq!(a.site_dynamic(), 25);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ban), ("rate", true), "1000 >= 3 x 300");
}

#[test]
fn site_tracking_is_bounded() {
    let mut a = IpAgg::default();
    for site in 0..(MAX_SITES as u64 + 20) {
        send(&mut a, site, "GET", "/", 200, BROWSER, 2);
    }
    assert_eq!(a.sites.len(), MAX_SITES);
    assert_eq!(
        a.dynamic(),
        2 * (MAX_SITES as u64 + 20),
        "the total counts them all"
    );
    let mut a = IpAgg::default();
    for i in 0..100 {
        send(&mut a, 0, "GET", "/", 200, &format!("Mozilla/5.0 B/{i}"), 1);
    }
    assert_eq!(a.browser_uas.len(), BROWSER_UA_CAP);
}

#[test]
fn while_the_baseline_learns_a_rate_hit_is_reported_unless_it_is_a_real_flood() {
    let learning = Judge {
        baseline_ready: false,
        ..ready()
    };
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/?s=x", 200, "curl/8.5", 1500);
    let h = judge(&a, &learning).unwrap();
    assert_eq!((h.reason, h.ban), ("rate", false));
    // Ten requests a second for the whole cycle bans even now.
    send(&mut a, 1, "GET", "/?s=x", 200, "curl/8.5", 1500);
    let h = judge(&a, &learning).unwrap();
    assert_eq!((h.reason, h.ban, h.escalate), ("rate", true, true));
    // A pattern that bans is not hidden by a report-only rate hit.
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/?s=x", 200, BROWSER, 400);
    for p in ["/.env", "/.git/config", "/phpmyadmin/"] {
        send(&mut a, 1, "GET", p, 404, BROWSER, 1);
    }
    let h = judge(&a, &learning).unwrap();
    assert_eq!((h.reason, h.ban, h.ttl_secs), ("probe", true, 600));
}

#[test]
fn a_proxy_in_the_logs_is_reported_not_banned_unless_it_floods() {
    // A CDN edge that is not in trusted_proxies: many browsers, several sites.
    let mut a = IpAgg::default();
    for i in 0..30 {
        let ua = format!(
            "Mozilla/5.0 (Windows NT 10.0) Chrome/{}.0 Safari/537.36",
            100 + i
        );
        send(&mut a, i % 3, "GET", "/", 200, &ua, 10);
    }
    send(&mut a, 0, "GET", "/", 200, BROWSER, 1300);
    assert!(a.looks_like_proxy());
    assert!(a.site_dynamic() >= 4 * 300 && a.dynamic() < 3000);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ban), ("rate", false));
    // Past the absolute ceiling it is banned whatever it is.
    send(&mut a, 0, "GET", "/", 200, BROWSER, 1500);
    assert!(judge(&a, &ready()).unwrap().ban);
    // Twenty browsers on one site is a busy office, not a proxy.
    let mut a = IpAgg::default();
    for i in 0..30 {
        send(&mut a, 0, "GET", "/", 200, &format!("Mozilla/5.0 B/{i}"), 1);
    }
    assert!(!a.looks_like_proxy());
}

#[test]
fn a_backlog_cycle_judges_neither_rate_nor_scanner_but_still_bruteforce() {
    let backlog = Judge {
        volume: false,
        ..ready()
    };
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/?s=x", 200, BROWSER, 5000);
    for i in 0..40 {
        get(&mut a, &format!("/x{i}"), 404, BROWSER);
    }
    assert!(judge(&a, &backlog).is_none());
    send(&mut a, 1, "POST", "/wp-login.php", 200, BROWSER, 11);
    assert_eq!(judge(&a, &backlog).unwrap().reason, "bruteforce");
}

// ---- verified crawlers ------------------------------------------------------

#[test]
fn a_verified_crawler_gets_ten_times_the_bar_and_only_a_short_ban() {
    let crawler = Judge {
        crawler: true,
        ..ready()
    };
    let mut a = IpAgg::default();
    for site in 0..2 {
        send(
            &mut a,
            site,
            "GET",
            "/shop/?filter_color=red&orderby=price",
            200,
            GOOGLEBOT,
            1000,
        );
    }
    assert!(judge(&a, &crawler).is_none());
    // The same from an address that only claims to be Googlebot.
    assert_eq!(judge(&a, &ready()).unwrap().reason, "rate");
    // Far beyond: banned, briefly, off the ladder.
    send(&mut a, 0, "GET", "/shop/", 200, GOOGLEBOT, 2500);
    let h = judge(&a, &crawler).unwrap();
    assert_eq!(
        (h.reason, h.ban, h.escalate, h.ttl_secs),
        ("rate", true, false, 600)
    );
}

#[test]
fn a_verified_crawler_following_stale_links_is_reported_but_password_guessing_is_not_excused() {
    let crawler = Judge {
        crawler: true,
        ..ready()
    };
    let mut a = IpAgg::default();
    for i in 0..40 {
        get(&mut a, &format!("/old-product-{i}/"), 404, GOOGLEBOT);
    }
    let h = judge(&a, &crawler).unwrap();
    assert_eq!((h.reason, h.ban), ("scanner", false));
    assert!(judge(&a, &ready()).unwrap().ban, "unverified: banned");
    send(&mut a, 0, "POST", "/wp-login.php", 200, GOOGLEBOT, 11);
    assert_eq!(judge(&a, &crawler).unwrap().reason, "bruteforce");
}

// ---- bruteforce -------------------------------------------------------------

#[test]
fn bruteforce_detected() {
    let mut a = IpAgg::default();
    for _ in 0..11 {
        a.observe(
            &line(r#"1.2.3.4 - - [x] "POST /wp-login.php HTTP/1.1" 200 1 "-" "x""#),
            0,
        );
    }
    let hit = evaluate(&a, false, true).unwrap();
    assert_eq!(hit.reason, "bruteforce");
    assert!(hit.ban && hit.escalate);
    // A lockout plugin answering 403/429 is still a failure.
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/wp-login.php", 429, BROWSER, 11);
    assert_eq!(evaluate(&a, false, true).unwrap().reason, "bruteforce");
}

#[test]
fn successful_logins_and_protected_post_unlocks_are_not_password_guessing() {
    // Twelve shop staff logging in from the office at 8:00 (302 each), and
    // thirty students unlocking a shared protected post.
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/wp-login.php", 302, BROWSER, 12);
    send(
        &mut a,
        0,
        "POST",
        "/wp-login.php?action=postpass",
        302,
        IPHONE,
        30,
    );
    assert!(evaluate(&a, false, true).is_none());
    // A guessing run that gets redirects (a login plugin's) is still caught.
    send(&mut a, 0, "POST", "/wp-login.php", 302, "curl/8.5", 30);
    assert_eq!(evaluate(&a, false, true).unwrap().reason, "bruteforce");
}

#[test]
fn xmlrpc_from_jetpack_or_wordpress_is_not_guessing_but_a_multicall_flood_is() {
    // Automattic's own servers calling every Jetpack site on the VPS.
    let mut a = IpAgg::default();
    let jp = line_from(
        "192.0.84.33",
        "POST",
        "/xmlrpc.php?for=jetpack",
        200,
        "Jetpack by WordPress.com",
    );
    for site in 0..30 {
        for _ in 0..5 {
            a.observe(&jp, site);
        }
    }
    assert!(evaluate(&a, false, true).is_none());
    // Eleven pingbacks from another blog: reported, not banned.
    let mut a = IpAgg::default();
    send(
        &mut a,
        0,
        "POST",
        "/xmlrpc.php",
        200,
        "WordPress/6.5; https://blog.example",
        11,
    );
    let h = evaluate(&a, false, true).unwrap();
    assert_eq!((h.reason, h.ban), ("xmlrpc_pingback", false));
    // A spoofed WordPress/ User-Agent only raises the bar to 60.
    send(&mut a, 0, "POST", "/xmlrpc.php", 200, "WordPress/6.5", 50);
    assert_eq!(evaluate(&a, false, true).unwrap().reason, "bruteforce");
    // system.multicall guessing with an ordinary User-Agent: 11 is enough.
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/xmlrpc.php", 200, BROWSER, 11);
    assert_eq!(evaluate(&a, false, true).unwrap().reason, "bruteforce");
}

#[test]
fn guessing_spread_over_many_sites_is_caught_by_the_backstop() {
    let mut a = IpAgg::default();
    for site in 0..4 {
        send(&mut a, site, "POST", "/wp-login.php", 200, BROWSER, 8);
    }
    assert_eq!(
        evaluate(&a, false, true).unwrap().reason,
        "bruteforce",
        "32 > 30"
    );
    // An agency's staff with a few typos on three client sites.
    let mut a = IpAgg::default();
    for site in 0..3 {
        send(&mut a, site, "POST", "/wp-login.php", 200, BROWSER, 4);
        send(&mut a, site, "POST", "/wp-login.php", 302, BROWSER, 5);
    }
    assert!(evaluate(&a, false, true).is_none());
}

// ---- probes, scanners, tools ------------------------------------------------

#[test]
fn a_lone_probe_from_a_browser_is_only_reported() {
    // Any page can make a visitor's browser fetch /.env here, even a few
    // times; that alone must not ban the visitor.
    let mut a = IpAgg::default();
    get(&mut a, "/", 200, BROWSER);
    for _ in 0..3 {
        get(&mut a, "/.env", 404, BROWSER);
    }
    let hit = evaluate(&a, false, true).unwrap();
    assert_eq!(hit.reason, "probe");
    assert!(!hit.ban);
    assert_eq!(hit.ttl_secs, 0);
}

#[test]
fn a_probe_with_a_tool_or_missing_user_agent_bans() {
    for ua in ["sqlmap/1.7", "", "-"] {
        let mut a = IpAgg::default();
        get(&mut a, "/.env", 404, ua);
        let hit = evaluate(&a, false, true).unwrap();
        assert_eq!((hit.reason, hit.ban, hit.ttl_secs), ("probe", true, 86_400));
        assert!(hit.escalate, "{ua:?}");
    }
}

#[test]
fn one_request_without_a_user_agent_does_not_taint_the_browsers_on_that_address() {
    // A browser that probed (a lured <img>) plus some other device's single
    // UA-less request on the same NAT address: not a probe ban.
    let mut a = IpAgg::default();
    get(&mut a, "/.env", 404, BROWSER);
    get(&mut a, "/webhook", 200, "");
    for _ in 0..60 {
        get(&mut a, "/san-pham/", 200, BROWSER);
    }
    assert!(evaluate(&a, false, true).is_none_or(|h| !h.ban));
    // A stock-sync job without a User-Agent calling the REST API 60 times.
    let mut a = IpAgg::default();
    for i in 0..60 {
        get(
            &mut a,
            &format!("/wp-json/wc/v3/products?page={i}"),
            200,
            "",
        );
    }
    assert!(evaluate(&a, false, true).is_none());
    // A UA-less scanner, most of whose requests miss, is still banned.
    let mut a = IpAgg::default();
    for i in 0..60 {
        get(&mut a, &format!("/admin{i}.php"), 404, "");
    }
    let h = evaluate(&a, false, true).unwrap();
    assert!(h.ban && h.escalate, "{h:?}");
}

#[test]
fn a_browser_lured_into_a_probe_sweep_gets_only_a_short_fixed_ban() {
    // What a page with a few <img> tags makes its visitor's browser send:
    // three probe kinds (or one, spelled three ways) and ten misses.
    let lures: [&[&str]; 2] = [
        &["/.env", "/.git/config", "/phpmyadmin/"],
        &["/.env", "//.env", "/.ENV/", "/.env?x=1"],
    ];
    for lure in lures {
        let mut a = IpAgg::default();
        for p in lure {
            get(&mut a, p, 404, BROWSER);
        }
        for i in 0..10 {
            get(&mut a, &format!("/old{i}.php"), 404, BROWSER);
        }
        let hit = evaluate(&a, false, true).unwrap();
        assert_eq!(hit.reason, "probe", "{lure:?}");
        assert!(hit.ttl_secs <= 600, "{lure:?}: {}", hit.ttl_secs);
        assert!(!hit.escalate, "{lure:?}");
    }

    // Three spellings, or three files, of one kind are one probe kind.
    for paths in [
        ["/.env", "//.env", "/.ENV/"],
        ["/.git/config", "/.git/HEAD", "/.git/index"],
    ] {
        let mut a = IpAgg::default();
        for p in paths {
            get(&mut a, p, 404, BROWSER);
        }
        assert!(!evaluate(&a, false, true).unwrap().ban, "{paths:?}");
    }

    // The same sweep with a tool's User-Agent is a day, on the ladder.
    let mut a = IpAgg::default();
    for p in ["/.env", "/.git/config", "/phpmyadmin/"] {
        get(&mut a, p, 404, "Mozilla/5.0 zgrab/0.x");
    }
    let hit = evaluate(&a, false, true).unwrap();
    assert_eq!((hit.ttl_secs, hit.escalate), (86_400, true));
}

#[test]
fn working_in_phpmyadmin_or_reading_a_post_about_it_is_not_a_probe() {
    // DirectAdmin's /phpmyadmin on a customer domain, used by its admin.
    let mut a = IpAgg::default();
    get(&mut a, "/phpmyadmin/index.php?route=/", 200, BROWSER);
    get(
        &mut a,
        "/phpmyadmin/js/vendor/jquery/jquery.min.js",
        200,
        BROWSER,
    );
    get(
        &mut a,
        "/phpmyadmin/themes/pmahomme/css/theme.css",
        200,
        BROWSER,
    );
    get(&mut a, "/phpMyAdmin/index.php", 200, BROWSER);
    get(&mut a, "/pma/sql.php", 200, BROWSER);
    assert_eq!(a.probe_hits, 0);
    assert!(evaluate(&a, false, true).is_none());
    // A hosting blog's posts about phpMyAdmin.
    let mut a = IpAgg::default();
    get(&mut a, "/phpmyadmin-la-gi/", 200, BROWSER);
    get(&mut a, "/phpmyadmin-la-gi/amp/", 200, BROWSER);
    get(&mut a, "/phpmyadmin-huong-dan/", 404, BROWSER);
    assert_eq!(a.probe_hits, 0);
    // A scanner looking for one that is not there still counts.
    let mut a = IpAgg::default();
    for p in ["/.env", "/.git/HEAD", "/phpMyAdmin-5.2.1/", "/pma/"] {
        get(&mut a, p, 404, "");
    }
    assert_eq!(a.probe_kinds.count_ones(), 3);
    assert_eq!(evaluate(&a, false, true).unwrap().ttl_secs, 86_400);
}

#[test]
fn a_scan_from_a_browser_user_agent_does_not_escalate() {
    let scan = |ua: &str| {
        let mut a = IpAgg::default();
        for i in 0..40 {
            get(&mut a, &format!("/x{i}"), 404, ua);
        }
        evaluate(&a, false, true).unwrap()
    };
    let hit = scan(BROWSER);
    assert_eq!(
        (hit.reason, hit.ban, hit.escalate),
        ("scanner", true, false)
    );
    assert!(hit.ttl_secs <= 3600);
    assert!(scan("").escalate);
}

#[test]
fn missing_images_after_a_migration_are_not_a_scan_but_missing_backups_are() {
    // A category page whose 40 thumbnails are gone, opened by one visitor.
    let mut a = IpAgg::default();
    get(&mut a, "/danh-muc/giay/", 200, BROWSER);
    for i in 0..40 {
        get(
            &mut a,
            &format!("/wp-content/uploads/2025/05/sp-{i}-300x300.webp"),
            404,
            BROWSER,
        );
    }
    assert!(evaluate(&a, false, true).is_none());
    // A sweep for backups and plugin readmes is.
    let mut a = IpAgg::default();
    for i in 0..20 {
        get(&mut a, &format!("/backup{i}.zip"), 404, "");
        get(
            &mut a,
            &format!("/wp-content/plugins/p{i}/readme.txt"),
            404,
            "",
        );
    }
    let h = evaluate(&a, false, true).unwrap();
    assert_eq!((h.reason, h.ban, h.escalate), ("scanner", true, true));
}

#[test]
fn scanner_needs_both_404_and_paths() {
    let mut a = IpAgg::default();
    for i in 0..40 {
        a.observe(
            &line(&format!(
                r#"1.2.3.4 - - [x] "GET /x{i} HTTP/1.1" 404 1 "-" "x""#
            )),
            0,
        );
    }
    assert_eq!(evaluate(&a, false, true).unwrap().reason, "scanner");
    let mut a = IpAgg::default();
    for _ in 0..40 {
        get(&mut a, "/same-missing-page/", 404, BROWSER);
    }
    assert!(evaluate(&a, false, true).is_none());
}

#[test]
fn one_request_from_an_audit_tool_does_not_ban_but_a_tool_run_does() {
    // The owner checks one site with WPScan: one request, answered.
    let mut a = IpAgg::default();
    get(
        &mut a,
        "/",
        200,
        "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
    );
    assert!(evaluate(&a, false, true).is_none());
    // A real run makes several requests or gets refused: an hour, escalating.
    for (status, times) in [(200, 3), (404, 1)] {
        let mut a = IpAgg::default();
        send(
            &mut a,
            0,
            "GET",
            "/wp-content/plugins/x/readme.txt",
            status,
            "sqlmap/1.7",
            times,
        );
        let h = evaluate(&a, false, true).unwrap();
        assert_eq!((h.reason, h.ttl_secs, h.escalate), ("bad_ua", 3600, true));
    }
}

#[test]
fn a_probe_does_not_hide_a_flood_from_the_rate_check() {
    // Busy address with one /.env: the probe decides nothing, so the rate
    // threshold decides.
    let mut a = IpAgg::default();
    for _ in 0..500 {
        get(&mut a, "/", 200, BROWSER);
    }
    get(&mut a, "/.env", 404, BROWSER);
    assert!(evaluate(&a, false, true).is_none());
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ban), ("rate", true));
}

#[test]
fn a_flood_is_rate_banned_whatever_else_it_matches() {
    // A non-escalating sweep cannot shield a flood from the rate ban, which
    // keeps the longer of the two lengths.
    let mut a = IpAgg::default();
    for p in ["/.env", "/.git/config", "/phpmyadmin/"] {
        get(&mut a, p, 404, BROWSER);
    }
    for i in 0..10 {
        get(&mut a, &format!("/old{i}.php"), 404, BROWSER);
    }
    let sweep = judge(&a, &ready()).unwrap();
    assert_eq!((sweep.reason, sweep.escalate), ("probe", false));
    send(&mut a, 0, "GET", "/?s=x", 200, "curl/8.5", 400);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!(
        (h.reason, h.ban, h.escalate, h.ttl_secs),
        ("rate", true, true, 600)
    );
    // A pattern that escalates keeps its own reason and length.
    let mut a = IpAgg::default();
    send(&mut a, 0, "GET", "/.env", 404, "sqlmap/1.7", 400);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ttl_secs), ("probe", 86_400));
}

#[test]
fn probe_paths_match_whole_segments() {
    for p in [
        "/.env",
        "/.ENV",
        "/.env.local",
        "/.env~",
        "/laravel/.env",
        "//.env/",
        "/.git/config",
        "/.git",
        "/app/.git/HEAD",
        "/.svn/entries",
        "/.aws/credentials",
        "/phpmyadmin",
        "/phpMyAdmin-5.2.1/index.php",
        "/phpmyadmin4.8/",
        "/pma/",
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/.DS_Store",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/lib/vendor/phpunit/x",
    ] {
        assert!(is_probe_path(p).is_some(), "{p}");
    }
    for p in [
        "/",
        "/config.json",
        "/assets/config.json",
        "/.envrc",
        "/blog/.environment",
        "/.github/logo.png",
        "/docs/phpmyadmin-guide",
        "/phpmyadmin-la-gi/",
        "/phpmyadminhelp",
        "/blog/pma/",
        "/wp-config.php",
        "/vendor/phpunit-docs",
        "/search",
    ] {
        assert!(is_probe_path(p).is_none(), "{p}");
    }
}

#[test]
fn pingback_is_report_only() {
    let mut a = IpAgg::default();
    for _ in 0..4 {
        a.observe(
            &line(r#"1.2.3.4 - - [x] "POST /xmlrpc.php HTTP/1.1" 200 1 "-" "WordPress/6.5""#),
            0,
        );
    }
    let hit = evaluate(&a, false, true).unwrap();
    assert_eq!(hit.reason, "xmlrpc_pingback");
    assert!(!hit.ban);
}

#[test]
fn user_agents_are_told_apart() {
    assert_eq!(classify_ua(""), UaClass::Empty);
    assert_eq!(classify_ua(" - "), UaClass::Empty);
    assert_eq!(
        classify_ua("Mozilla/5.0 Nuclei - Open-source project"),
        UaClass::Tool
    );
    assert_eq!(classify_ua(BROWSER), UaClass::Browser);
    assert_eq!(classify_ua(IPHONE), UaClass::Browser);
    assert_eq!(classify_ua(GOOGLEBOT), UaClass::Other);
    assert_eq!(
        classify_ua("Mozilla/5.0 HeadlessChrome/120"),
        UaClass::Other
    );
    assert_eq!(classify_ua("curl/8.5"), UaClass::Other);
    assert_eq!(classify_ua("WordPress/6.5; https://x"), UaClass::Other);
}
