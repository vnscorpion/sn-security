//! Each rule against the legitimate traffic it used to ban, and against the
//! attack it must still catch.

use super::*;
use snsec_common::logfmt::{LogFormat, parse_line};

const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0) Chrome/148.0.0.0 Safari/537.36";
/// What every Windows Chrome of one major version sends since the User-Agent
/// reduction: one string for a whole office.
const CHROME_REDUCED: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const ANDROID_REDUCED: &str = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36";
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
fn send(a: &mut IpAgg, site: u32, method: &str, path: &str, status: u16, ua: &str, times: usize) {
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
        span: 300,
        volume_exempt: false,
    }
}

fn eval(a: &IpAgg) -> Option<PatternHit> {
    evaluate(a, &ready())
}

/// One page view: the HTML, its CSS/JS, images and fonts, and the WooCommerce
/// cart fragments call. 66 lines, three of them dynamic.
fn page_view(a: &mut IpAgg, site: u32, ua: &str, page: &str) {
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
    // Home page and a 36-product category with thumbnails: ~170 lines used to
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
fn one_viewer_of_a_self_hosted_live_stream_is_no_flood() {
    // 2-second HLS segments and playlist refreshes for five minutes.
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/live/", 200, BROWSER, 1);
    for i in 0..300 {
        send(
            &mut a,
            1,
            "GET",
            &format!("/live/seg-{i}.ts"),
            200,
            BROWSER,
            1,
        );
    }
    send(&mut a, 1, "GET", "/live/index.m3u8", 200, BROWSER, 150);
    send(&mut a, 1, "GET", "/dash/chunk-1.m4s", 200, BROWSER, 50);
    send(&mut a, 1, "GET", "/dash/manifest.mpd", 200, BROWSER, 20);
    send(&mut a, 1, "GET", "/files/guide.pdf", 206, BROWSER, 40);
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
    for p in [
        "/a.css",
        "/x/y.PNG",
        "/f.woff2",
        "/v.mp4",
        "/s.js.map",
        "/hls/seg-001.ts",
        "/live/index.m3u8",
        "/dash/chunk.m4s",
        "/manifest.mpd",
        "/a.pdf",
        "/x/../a.css",
        "/a.css?x=1",
        "/a%2ecss",
    ] {
        assert!(is_asset(p), "{p}");
    }
    for p in [
        "/",
        "/sitemap.xml",
        "/readme.txt",
        "/db.sql",
        "/index.php",
        "/a.css/",
        // PATH_INFO: the script runs, whatever the name after it.
        "/wp-login.php/x.css",
        "/xmlrpc.php/a.png",
        "/index.php/wp-content/x.png",
        "/WP-LOGIN.PHP/x.jpg",
    ] {
        assert!(!is_asset(p), "{p}");
    }
}

#[test]
fn paths_are_read_the_way_the_server_resolves_them() {
    let norm = |p: &str| ReqPath::of(p).norm;
    assert_eq!(norm("/"), "/");
    assert_eq!(norm("/?s=x"), "/");
    assert_eq!(norm("/a/b/"), "/a/b");
    assert_eq!(norm("//wp-login.php"), "/wp-login.php");
    assert_eq!(norm("/blog/../wp-login.php"), "/wp-login.php");
    assert_eq!(norm("/./a/./b"), "/a/b");
    assert_eq!(norm("/../../etc/passwd"), "/etc/passwd");
    assert_eq!(norm("/wp-login%2ephp"), "/wp-login.php");
    assert_eq!(norm("/%2e%2E/x%2Fy"), "/x/y");
    assert_eq!(norm("/bad%zz%2"), "/bad%zz%2");
    assert_eq!(norm("/x#frag"), "/x");
    for (p, script) in [
        ("/wp-login.php", Some("wp-login.php")),
        ("/wp-login.php/", Some("wp-login.php")),
        ("/wp-login.php/x.css", Some("wp-login.php")),
        ("/blog/WP-LOGIN.PHP", Some("WP-LOGIN.PHP")),
        ("/a/b.php/c.php", Some("b.php")),
        ("/x.css", None),
        ("/.php", None),
    ] {
        assert_eq!(ReqPath::of(p).script(), script, "{p}");
    }
    assert!(ReqPath::of("/wp-admin/").is_admin_page());
    assert!(ReqPath::of("/blog/wp-admin/post.php?post=5").is_admin_page());
    for p in [
        "/wp-admin/admin-ajax.php",
        "/wp-admin/install.php",
        "/wp-admin/maint/repair.php",
        "/wp-admin/css/x.css",
        "/wp-login.php",
    ] {
        assert!(!ReqPath::of(p).is_admin_page(), "{p}");
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
    // An upgraded VPS still on the old floor of 120: the line bar never drops
    // below 3000 a cycle.
    let old = Judge {
        threshold: 120,
        ..ready()
    };
    assert!(judge(&a, &old).is_none());
}

#[test]
fn a_flood_of_missing_assets_rendered_by_wordpress_is_banned_but_missing_thumbnails_are_not() {
    // `/r123.css` misses go to index.php on Apache/LiteSpeed: a full WordPress
    // render each, three a second.
    let mut a = IpAgg::default();
    for i in 0..900 {
        send(&mut a, 1, "GET", &format!("/r{i}.css"), 404, BROWSER, 1);
    }
    assert_eq!(a.dynamic(), 0);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ban), ("rate", true));
    // A visitor going through five category pages whose 40 thumbnails each
    // are gone after a migration.
    let mut a = IpAgg::default();
    for page in 0..5 {
        send(
            &mut a,
            1,
            "GET",
            &format!("/danh-muc/c{page}/"),
            200,
            BROWSER,
            1,
        );
        for i in 0..40 {
            send(
                &mut a,
                1,
                "GET",
                &format!("/wp-content/uploads/2025/05/sp-{page}-{i}-300x300.webp"),
                404,
                BROWSER,
                1,
            );
        }
    }
    assert!(judge(&a, &ready()).is_none());
}

#[test]
fn a_carrier_nat_browsing_many_pages_gets_a_higher_bar_and_a_short_ban() {
    // Three people on one 4G address browsing the same shop, each fetching
    // the pages' images.
    let mut a = IpAgg::default();
    for ua in [
        BROWSER,
        IPHONE,
        "Mozilla/5.0 (Linux; Android 15) Chrome/147.0 Mobile Safari/537.36",
    ] {
        send(&mut a, 1, "GET", "/wp-content/uploads/logo.png", 200, ua, 1);
        for i in 0..250 {
            send(&mut a, 1, "GET", &format!("/san-pham/{i}/"), 200, ua, 1);
        }
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
fn an_office_on_one_chrome_version_rendering_pages_is_not_one_person() {
    // Four shop staff on one office address, all on managed Chrome, so one
    // User-Agent: processing WooCommerce orders (each order screen is the
    // page, its assets and a few wc-admin REST calls).
    let mut a = IpAgg::default();
    for i in 0..36 {
        page_view(
            &mut a,
            1,
            CHROME_REDUCED,
            &format!("/wp-admin/post.php?post={i}&action=edit"),
        );
        send(
            &mut a,
            1,
            "GET",
            "/wp-json/wc-admin/orders?_locale=user",
            200,
            CHROME_REDUCED,
            8,
        );
    }
    assert_eq!(a.site_dynamic(), 396);
    assert_eq!(a.clients(), 2);
    assert!(judge(&a, &ready()).is_none(), "396 < 2 x 300");
    // Busier still: a short ban that never climbs.
    send(
        &mut a,
        1,
        "GET",
        "/wp-json/wc-admin/orders?_locale=user",
        200,
        CHROME_REDUCED,
        304,
    );
    let h = judge(&a, &ready()).unwrap();
    assert_eq!(
        (h.reason, h.ban, h.escalate, h.ttl_secs),
        ("rate", true, false, 600)
    );
}

#[test]
fn shoppers_behind_one_carrier_address_with_the_same_phone_browser_are_no_static_flood() {
    // Eight Android phones on one CGNAT address, one reduced User-Agent,
    // six page views each with cold caches: over 3000 lines, few dynamic.
    let mut a = IpAgg::default();
    for shopper in 0..8 {
        for p in 0..6 {
            page_view(
                &mut a,
                1,
                ANDROID_REDUCED,
                &format!("/san-pham/{shopper}-{p}/"),
            );
        }
    }
    assert!(a.lines() > 3000, "{}", a.lines());
    assert_eq!(a.dynamic(), 144);
    assert!(judge(&a, &ready()).is_none());
}

#[test]
fn an_agency_working_on_twenty_client_sites_is_judged_site_by_site() {
    // Staff on one Chrome User-Agent opening wp-admin screens with cold caches
    // on twenty sites of this VPS: ~16 000 lines, 40 dynamic per site.
    let mut a = IpAgg::default();
    for site in 0..20 {
        for page in 0..12 {
            page_view(
                &mut a,
                site,
                CHROME_REDUCED,
                &format!("/wp-admin/post.php?post={page}"),
            );
        }
    }
    assert!(a.lines() > 15_000);
    assert!(judge(&a, &ready()).is_none());
    // Four people with four different browsers: the same.
    let mut a = IpAgg::default();
    for site in 0..20 {
        for (i, ua) in [BROWSER, CHROME_REDUCED, IPHONE, ANDROID_REDUCED]
            .iter()
            .enumerate()
        {
            for page in 0..3 {
                page_view(
                    &mut a,
                    site,
                    ua,
                    &format!("/wp-admin/edit.php?p={i}-{page}"),
                );
            }
        }
    }
    assert!(judge(&a, &ready()).is_none());
}

#[test]
fn rotating_user_agents_gains_nothing_without_rendering_pages() {
    // 400 Chrome User-Agents, none of which ever fetched an image or a script.
    let mut a = IpAgg::default();
    for i in 0..400 {
        let ua = format!("Mozilla/5.0 (Windows NT 10.0) Chrome/{i}.0 Safari/537.36");
        send(&mut a, 1, "GET", &format!("/?p={i}"), 200, &ua, 3);
    }
    assert_eq!(a.clients(), 1);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ban, h.escalate), ("rate", true, true));
    // Fetching one image per User-Agent raises the bar at most four times, and
    // over a few paths it is still no NAT and no proxy: it climbs the ladder.
    let mut a = IpAgg::default();
    for i in 0..24 {
        let ua = format!(
            "Mozilla/5.0 (Windows NT 10.0) Chrome/{}.0 Safari/537.36",
            100 + i
        );
        send(&mut a, 1, "GET", "/logo.png", 200, &ua, 1);
        send(&mut a, 1, "GET", "/?s=x", 200, &ua, 60);
    }
    send(&mut a, 2, "GET", "/", 200, BROWSER, 1);
    send(&mut a, 3, "GET", "/", 200, BROWSER, 1);
    assert_eq!(a.clients(), MAX_CLIENTS);
    assert!(!a.looks_like_proxy());
    let h = judge(&a, &ready()).unwrap();
    assert_eq!(
        (h.reason, h.ban, h.escalate),
        ("rate", true, true),
        "1440 >= 4 x 300"
    );
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
fn what_one_address_keeps_is_bounded() {
    let mut a = IpAgg::default();
    for site in 0..(MAX_SITES as u32 + 20) {
        send(&mut a, site, "GET", "/", 200, BROWSER, 2);
    }
    assert_eq!(a.sites.len(), MAX_SITES);
    assert!(a.sites.more.capacity() < MAX_SITES);
    assert_eq!(
        a.dynamic(),
        2 * (MAX_SITES as u64 + 20),
        "the total counts them all"
    );
    let mut a = IpAgg::default();
    for i in 0..100 {
        send(
            &mut a,
            0,
            "GET",
            &format!("/p{i}"),
            200,
            &format!("Mozilla/5.0 B/{i}"),
            1,
        );
    }
    assert_eq!(a.browser_uas.len(), BROWSER_UA_CAP);
    assert_eq!(a.paths.len(), PATH_CAP);
    assert_eq!(a.distinct_paths(), PATH_CAP + 1);
    // A flood of addresses (an IPv6 /48 has 65 536 /64s) costs little each.
    assert!(
        std::mem::size_of::<IpAgg>() <= 256,
        "{}",
        std::mem::size_of::<IpAgg>()
    );
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
fn the_ceiling_bans_whatever_threshold_the_baseline_learned() {
    // A threshold pushed up by someone who flooded while it was learning.
    let poisoned = Judge {
        threshold: 15_000,
        ..ready()
    };
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/?s=x", 200, "curl/8.5", 3000);
    let h = judge(&a, &poisoned).unwrap();
    assert_eq!((h.reason, h.ban), ("rate", true));
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/?s=x", 200, "curl/8.5", 2999);
    assert!(judge(&a, &poisoned).is_none());
}

#[test]
fn a_proxy_in_the_logs_is_reported_not_banned_unless_it_floods() {
    // A CDN edge that is not in trusted_proxies, in front of one site: many
    // browsers rendering many pages.
    let mut a = IpAgg::default();
    for i in 0..30 {
        let ua = format!(
            "Mozilla/5.0 (Windows NT 10.0) Chrome/{}.0 Safari/537.36",
            100 + i
        );
        page_view(&mut a, 0, &ua, &format!("/p{i}/"));
    }
    send(&mut a, 0, "GET", "/", 200, BROWSER, 1300);
    assert!(a.looks_like_proxy());
    assert!(a.site_dynamic() >= 4 * 300 && a.dynamic() < 3000);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ban), ("rate", false));
    // Past the absolute ceiling it is banned whatever it is, briefly.
    send(&mut a, 0, "GET", "/", 200, BROWSER, 1700);
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.ban, h.escalate), (true, false));
    // Thirty browsers that never fetched an asset are no proxy.
    let mut a = IpAgg::default();
    for i in 0..30 {
        send(
            &mut a,
            0,
            "GET",
            &format!("/x{i}"),
            200,
            &format!("Mozilla/5.0 B/{i}"),
            2,
        );
    }
    assert!(!a.looks_like_proxy());
}

#[test]
fn a_backlog_cycle_judges_neither_rate_nor_scanner_but_still_bruteforce() {
    let backlog = Judge {
        volume: false,
        span: 3600,
        ..ready()
    };
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/?s=x", 200, BROWSER, 5000);
    for i in 0..40 {
        get(&mut a, &format!("/x{i}"), 404, BROWSER);
    }
    assert!(judge(&a, &backlog).is_none());
    // An hour of log: the bar is an hour's worth too.
    send(&mut a, 1, "POST", "/wp-login.php", 200, BROWSER, 120);
    assert!(judge(&a, &backlog).is_none(), "120 in an hour");
    send(&mut a, 1, "POST", "/wp-login.php", 200, BROWSER, 1);
    assert_eq!(judge(&a, &backlog).unwrap().reason, "bruteforce");
}

#[test]
fn the_other_rules_scale_with_the_stretch_of_log_too() {
    let ten_minutes = Judge {
        span: 600,
        ..ready()
    };
    let mut a = IpAgg::default();
    send(&mut a, 1, "POST", "/wp-login.php", 200, BROWSER, 20);
    assert!(evaluate(&a, &ten_minutes).is_none());
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
    send(&mut a, 1, "POST", "/wp-login.php", 200, BROWSER, 1);
    assert_eq!(evaluate(&a, &ten_minutes).unwrap().reason, "bruteforce");
    // 61 protected-post unlocks over ten minutes are a busy class, not abuse.
    let mut a = IpAgg::default();
    send(
        &mut a,
        1,
        "POST",
        "/wp-login.php?action=postpass",
        302,
        IPHONE,
        61,
    );
    assert!(evaluate(&a, &ten_minutes).is_none());
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
}

#[test]
fn an_exempt_address_is_only_reported_for_volume_unless_it_floods() {
    // An open panel or FTP session, or an address the admin just unbanned.
    let exempt = Judge {
        volume_exempt: true,
        ..ready()
    };
    let mut a = IpAgg::default();
    send(&mut a, 1, "GET", "/?s=x", 200, BROWSER, 1000);
    for i in 0..40 {
        get(&mut a, &format!("/x{i}"), 404, "curl/8.5");
    }
    let h = judge(&a, &exempt).unwrap();
    assert_eq!((h.reason, h.ban), ("rate", false));
    assert!(!evaluate(&a, &exempt).unwrap().ban, "scanner reported");
    // Ten a second is banned anyway.
    send(&mut a, 1, "GET", "/?s=x", 200, BROWSER, 2000);
    assert!(judge(&a, &exempt).unwrap().ban);
    // Password guessing and probes are never exempt.
    let mut a = IpAgg::default();
    send(&mut a, 1, "POST", "/wp-login.php", 200, BROWSER, 11);
    assert_eq!(judge(&a, &exempt).unwrap().reason, "bruteforce");
    let mut a = IpAgg::default();
    get(&mut a, "/.env", 404, "curl/8.5");
    assert_eq!(judge(&a, &exempt).unwrap().reason, "probe");
}

// ---- crawlers -----------------------------------------------------------------

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
    // The same from an address that only claims to be Googlebot: banned, but
    // never up the ladder (the claim gains only that).
    let h = judge(&a, &ready()).unwrap();
    assert_eq!((h.reason, h.ban, h.escalate), ("rate", true, false));
    // Far beyond: banned, briefly, off the ladder.
    send(&mut a, 0, "GET", "/shop/", 200, GOOGLEBOT, 2500);
    let h = judge(&a, &crawler).unwrap();
    assert_eq!(
        (h.reason, h.ban, h.escalate, h.ttl_secs),
        ("rate", true, false, 600)
    );
}

#[test]
fn a_crawler_that_is_not_verified_by_address_is_not_put_on_the_ladder_for_volume() {
    // facebookexternalhit, Cốc Cốc, Yandex...: not in any embedded list.
    for ua in [
        "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
        "Mozilla/5.0 (compatible; coccocbot-web/1.0; +http://help.coccoc.com/searchengine)",
        "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    ] {
        let mut a = IpAgg::default();
        for i in 0..400 {
            send(&mut a, 1, "GET", &format!("/san-pham/{i}/"), 200, ua, 1);
        }
        let h = judge(&a, &ready()).unwrap();
        assert_eq!(
            (h.reason, h.ban, h.escalate, h.ttl_secs),
            ("rate", true, false, 600),
            "{ua}"
        );
        // Its probes are probes all the same.
        get(&mut a, "/.env", 404, ua);
        let h = judge(&a, &ready()).unwrap();
        assert_eq!((h.reason, h.escalate), ("probe", true), "{ua}");
    }
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
    let h = judge(&a, &ready()).unwrap();
    assert_eq!(
        (h.reason, h.ban, h.escalate),
        ("scanner", true, false),
        "unverified"
    );
    // A link to /.env somewhere: a verified crawler that follows it is not
    // banned for the day a library or a bot by name gets...
    let mut alone = IpAgg::default();
    get(&mut alone, "/.env", 404, GOOGLEBOT);
    assert!(!judge(&alone, &crawler).unwrap().ban);
    assert!(judge(&alone, &ready()).unwrap().ban, "unverified");
    // ...but a probe among many misses is the short sweep ban for it too.
    get(&mut a, "/.env", 404, GOOGLEBOT);
    let h = judge(&a, &crawler).unwrap();
    assert_eq!((h.reason, h.ban, h.escalate), ("probe", true, false));
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
    let hit = eval(&a).unwrap();
    assert_eq!(hit.reason, "bruteforce");
    assert!(hit.ban && hit.escalate);
    // A lockout plugin answering 403/429 is still a failure.
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/wp-login.php", 429, BROWSER, 11);
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
}

#[test]
fn successful_logins_and_protected_post_unlocks_are_not_password_guessing() {
    // Twelve shop staff logging in from the office at 8:00 (302, then the
    // dashboard), and thirty students unlocking a shared protected post.
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/wp-login.php", 302, BROWSER, 12);
    send(&mut a, 0, "GET", "/wp-admin/", 200, BROWSER, 12);
    send(
        &mut a,
        0,
        "POST",
        "/wp-login.php?action=postpass",
        302,
        IPHONE,
        30,
    );
    assert!(eval(&a).is_none());
    // The same staff on a site with a two-factor plugin: the password step
    // answers 200 (the code form), the code step redirects.
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/wp-login.php", 200, BROWSER, 12);
    send(
        &mut a,
        0,
        "POST",
        "/wp-login.php?action=validate_2fa",
        302,
        BROWSER,
        12,
    );
    send(&mut a, 0, "GET", "/wp-admin/index.php", 200, BROWSER, 12);
    assert!(eval(&a).is_none());
    // Thirty students logging in to a course site (sent to the front end,
    // not to wp-admin).
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/wp-login.php", 302, IPHONE, 30);
    assert!(eval(&a).is_none());
    // Password resets answer 200 too: a few are nothing.
    let mut a = IpAgg::default();
    send(
        &mut a,
        0,
        "POST",
        "/wp-login.php?action=resetpass",
        200,
        BROWSER,
        3,
    );
    assert!(eval(&a).is_none());
}

#[test]
fn guessing_that_gets_redirects_is_still_guessing() {
    // A login plugin that redirects failed logins (?login=failed): nothing
    // logged in follows.
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/wp-login.php", 302, "curl/8.5", 31);
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
    // Guesses padded with redirects the attacker can cause at will (a
    // protected-post unlock sent in the body): the padding excuses nothing.
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/wp-login.php", 200, BROWSER, 11);
    send(&mut a, 0, "POST", "/wp-login.php", 302, BROWSER, 11);
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
    // Nor do admin URLs that answer anyone.
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/wp-login.php", 200, BROWSER, 11);
    send(
        &mut a,
        0,
        "POST",
        "/wp-login.php?action=x",
        302,
        BROWSER,
        11,
    );
    send(&mut a, 0, "GET", "/wp-admin/install.php", 200, BROWSER, 11);
    send(
        &mut a,
        0,
        "GET",
        "/wp-admin/admin-ajax.php",
        200,
        BROWSER,
        11,
    );
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
    // A query that says postpass on a login that failed (200) is a failure.
    let mut a = IpAgg::default();
    send(
        &mut a,
        0,
        "POST",
        "/wp-login.php?action=postpass",
        200,
        BROWSER,
        11,
    );
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
}

#[test]
fn a_login_hidden_behind_path_info_or_encoding_is_a_login() {
    for path in [
        "/wp-login.php/x.css",
        "/wp-login.php/",
        "/wp-login%2ephp",
        "//blog/../wp-login.php",
        "/WP-LOGIN.PHP",
        "/blog/wp-login.php/a.png?x=1",
    ] {
        let mut a = IpAgg::default();
        send(&mut a, 0, "POST", path, 200, "curl/8.5", 11);
        assert_eq!(a.login_posts, 11, "{path}");
        assert_eq!(eval(&a).unwrap().reason, "bruteforce", "{path}");
    }
    // Four rotating browsers do not hide it either.
    let mut a = IpAgg::default();
    for i in 0..11 {
        let ua = format!("Mozilla/5.0 (Windows NT 10.0) Chrome/{}.0", i % 4);
        send(&mut a, 1, "POST", "/wp-login.php/", 200, &ua, 1);
    }
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/xmlrpc.php/a.png", 200, BROWSER, 11);
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
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
    assert!(eval(&a).is_none());
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
    let h = eval(&a).unwrap();
    assert_eq!((h.reason, h.ban), ("xmlrpc_pingback", false));
    // A spoofed WordPress/ User-Agent only raises the bar to 20.
    send(&mut a, 0, "POST", "/xmlrpc.php", 200, "WordPress/6.5", 10);
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
    // "Jetpack" in the User-Agent from anyone else is no excuse.
    let mut a = IpAgg::default();
    send(
        &mut a,
        0,
        "POST",
        "/xmlrpc.php",
        200,
        "Jetpack by WordPress.com",
        11,
    );
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
    // system.multicall guessing with an ordinary User-Agent: 11 is enough.
    let mut a = IpAgg::default();
    send(&mut a, 0, "POST", "/xmlrpc.php", 200, BROWSER, 11);
    assert_eq!(eval(&a).unwrap().reason, "bruteforce");
}

#[test]
fn guessing_spread_over_many_sites_is_caught_by_the_backstop() {
    let mut a = IpAgg::default();
    for site in 0..4 {
        send(&mut a, site, "POST", "/wp-login.php", 200, BROWSER, 8);
    }
    assert_eq!(eval(&a).unwrap().reason, "bruteforce", "32 > 30");
    // An agency's staff with a few typos on three client sites.
    let mut a = IpAgg::default();
    for site in 0..3 {
        send(&mut a, site, "POST", "/wp-login.php", 200, BROWSER, 4);
        send(&mut a, site, "POST", "/wp-login.php", 302, BROWSER, 5);
        send(&mut a, site, "GET", "/wp-admin/", 200, BROWSER, 5);
    }
    assert!(eval(&a).is_none());
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
    let hit = eval(&a).unwrap();
    assert_eq!(hit.reason, "probe");
    assert!(!hit.ban);
    assert_eq!(hit.ttl_secs, 0);
}

#[test]
fn a_probe_with_a_tool_a_library_or_no_user_agent_bans() {
    for ua in [
        "sqlmap/1.7",
        "",
        "-",
        "python-requests/2.31",
        "Go-http-client/1.1",
        "curl/8.5",
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
    ] {
        let mut a = IpAgg::default();
        get(&mut a, "/.env", 404, ua);
        let hit = eval(&a).unwrap();
        assert_eq!(
            (hit.reason, hit.ban, hit.ttl_secs),
            ("probe", true, 86_400),
            "{ua:?}"
        );
        assert!(hit.escalate, "{ua:?}");
    }
}

#[test]
fn a_small_secrets_sweep_from_an_http_library_is_banned() {
    for ua in ["python-requests/2.31", "Go-http-client/1.1", "curl/8.5"] {
        let mut a = IpAgg::default();
        for p in [
            "/.env",
            "/api/.env",
            "/.env.bak",
            "/laravel/.env",
            "/.git/config",
            "/.git/HEAD",
            "/backend/.env",
            "/.env.production",
            "/app/.env",
        ] {
            get(&mut a, p, 404, ua);
        }
        let h = eval(&a).unwrap();
        assert_eq!((h.reason, h.ban, h.escalate), ("probe", true, true), "{ua}");
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
    assert!(eval(&a).is_none_or(|h| !h.ban));
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
    assert!(eval(&a).is_none());
    // A UA-less scanner, most of whose requests miss, is still banned.
    let mut a = IpAgg::default();
    for i in 0..60 {
        get(&mut a, &format!("/admin{i}.php"), 404, "");
    }
    let h = eval(&a).unwrap();
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
        let hit = eval(&a).unwrap();
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
        assert!(!eval(&a).unwrap().ban, "{paths:?}");
    }

    // The same sweep with a tool's User-Agent is a day, on the ladder.
    let mut a = IpAgg::default();
    for p in ["/.env", "/.git/config", "/phpmyadmin/"] {
        get(&mut a, p, 404, "Mozilla/5.0 zgrab/0.x");
    }
    let hit = eval(&a).unwrap();
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
    assert!(eval(&a).is_none());
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
    assert_eq!(eval(&a).unwrap().ttl_secs, 86_400);
}

#[test]
fn a_scan_from_a_browser_user_agent_does_not_escalate() {
    let scan = |ua: &str| {
        let mut a = IpAgg::default();
        for i in 0..40 {
            get(&mut a, &format!("/x{i}"), 404, ua);
        }
        eval(&a).unwrap()
    };
    let hit = scan(BROWSER);
    assert_eq!(
        (hit.reason, hit.ban, hit.escalate),
        ("scanner", true, false)
    );
    assert!(hit.ttl_secs <= 3600);
    assert!(scan("").escalate);
    assert!(scan("python-requests/2.31").escalate);
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
    assert!(eval(&a).is_none());
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
    let h = eval(&a).unwrap();
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
    assert_eq!(eval(&a).unwrap().reason, "scanner");
    let mut a = IpAgg::default();
    for _ in 0..40 {
        get(&mut a, "/same-missing-page/", 404, BROWSER);
    }
    assert!(eval(&a).is_none());
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
    assert!(eval(&a).is_none());
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
        let h = eval(&a).unwrap();
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
    assert!(eval(&a).is_none());
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
    // Encoded, the way the server reads them.
    for p in ["/%2eenv", "/.git%2fconfig", "/x/..%2f.env"] {
        assert!(is_probe_path(&ReqPath::of(p).norm).is_some(), "{p}");
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
    let hit = eval(&a).unwrap();
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
    assert_eq!(classify_ua(CHROME_REDUCED), UaClass::Browser);
    assert_eq!(classify_ua(GOOGLEBOT), UaClass::Other);
    assert_eq!(
        classify_ua("Mozilla/5.0 HeadlessChrome/120"),
        UaClass::Other
    );
    assert_eq!(classify_ua("curl/8.5"), UaClass::Other);
    assert_eq!(classify_ua("WordPress/6.5; https://x"), UaClass::Other);
}
