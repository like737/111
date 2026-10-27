"""
URL 小工具（guard 自用, 不依赖 eyilianjie, 保证即使 eyilianjie 模块不可用也能拦截）
"""

from urllib.parse import urlsplit, urlunsplit

# 常见的多段后缀（用于取"注册域"）——只做保守判断, 取不到就退化为后两段
_MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.tw", "org.tw", "com.hk", "org.hk", "com.au", "com.br",
    "com.sg", "com.my", "co.kr", "co.in", "com.tr", "com.mx",
}

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def ensure_scheme(url):
    """补全协议（用于把纯域名/裸路径当 URL 处理）"""
    text = (url or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text.lstrip("/")
    return text


def host_of(url):
    """取主机名（小写、去端口）"""
    try:
        parts = urlsplit(ensure_scheme(url))
        return (parts.hostname or "").lower().strip(".")
    except Exception:
        return ""


def is_local_host(host):
    """本机地址（这类请求不做拦截判定, 直连放行）"""
    host = (host or "").lower()
    if host in _LOCAL_HOSTS:
        return True
    return host.endswith(".local") or host.endswith(".localhost")


def norm_url(url):
    """规范化: 小写协议与主机、去默认端口、去 fragment"""
    try:
        parts = urlsplit(ensure_scheme(url))
    except Exception:
        return (url or "").strip()
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if not host:
        return (url or "").strip()
    port = ""
    if parts.port and not ((scheme == "http" and parts.port == 80) or
                           (scheme == "https" and parts.port == 443)):
        port = ":%d" % parts.port
    path = parts.path or "/"
    return urlunsplit((scheme, host + port, path, parts.query, ""))


def parent_domains(host, keep_levels=2):
    """逐级剥离子域名: a.b.c.com -> [a.b.c.com, b.c.com, c.com]（至少保留 keep_levels 段）"""
    host = (host or "").lower().strip(".")
    if not host:
        return []
    labels = host.split(".")
    out = []
    for i in range(0, max(1, len(labels) - keep_levels + 1)):
        out.append(".".join(labels[i:]))
    return out


def registrable_domain(host):
    """取注册域（保守实现）: www.a.co.uk -> a.co.uk"""
    host = (host or "").lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def path_parents(normed_url):
    """父路径链（用于"名单收的是目录"的匹配）: /a/b/c -> ['/a/b/c', '/a/b', '/a']"""
    try:
        parts = urlsplit(normed_url)
    except Exception:
        return []
    path = parts.path or "/"
    segments = [seg for seg in path.split("/") if seg]
    out = []
    for i in range(len(segments), 0, -1):
        out.append("/" + "/".join(segments[:i]))
    return out


def without_query(normed_url):
    try:
        parts = urlsplit(normed_url)
    except Exception:
        return normed_url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
