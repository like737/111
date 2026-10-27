# 引擎体检报告（阈值 60）

样本：正（黑名单域名）12230 ｜ 负（domain_test_neg_clean.tsv）36773 ｜ 真实流量 10

- 整体召回：3337/12230 = **27.29%**
- 整体误报：3/36773 = **0.008%**

## 1) 分类别召回

| 分类 | 总数 | 命中 | 召回 |
|---|---|---|---|
| 色情网站 | 11583 | 3309 | 28.57% |
| 恶意URL | 627 | 28 | 4.47% |
| 钓鱼网站 | 20 | 0 | 0.00% |

## 2) 每条规则（lift = 正命中率 ÷ 负命中率）

| 规则 | 正命中 | 负命中 | 正命中率 | 负命中率 | lift | 判定 |
|---|---|---|---|---|---|---|
| adult_content | 3379 | 7 | 27.63% | 0.019% | 1451.4 | 很专一 |
| suspicious_tld | 1621 | 1024 | 13.25% | 2.785% | 4.8 | 有效 |
| subdomain | 451 | 308 | 3.69% | 0.838% | 4.4 | 有效 |
| dga | 176 | 1507 | 1.44% | 4.098% | 0.4 | **误报源** |
| typosquatting | 112 | 439 | 0.92% | 1.194% | 0.8 | **误报源** |
| keywords | 63 | 172 | 0.52% | 0.468% | 1.1 | **误报源** |
| special_chars | 17 | 140 | 0.14% | 0.381% | 0.4 | **误报源** |
| deceptive_domain | 13 | 0 | 0.11% | 0.000% | 1063.0 | 很专一 |
| pattern_library | 11 | 9 | 0.09% | 0.024% | 3.7 | 有效 |
| free_hosting | 10 | 1 | 0.08% | 0.003% | 30.1 | 很专一 |
| shortener | 0 | 1 | 0.00% | 0.003% | 0.0 | 偏弱 |

## 3) 阈值敏感性

| 阈值 | 正召回 | 负误报 | 真实流量误报 |
|---|---|---|---|
| 40 | 27.67% (3384) | 0.177% (65) | 2 |
| 50 | 27.43% (3355) | 0.073% (27) | 2 |
| 55 | 27.31% (3340) | 0.019% (7) | 2 |
| 60 | 27.29% (3337) | 0.008% (3) | 2 |
| 65 | 27.28% (3336) | 0.000% (0) | 2 |
| 70 | 27.28% (3336) | 0.000% (0) | 2 |
| 80 | 27.28% (3336) | 0.000% (0) | 2 |

## 4) 覆盖缺口

- 抓不到：8893/12230（72.71%）
- 漏掉的样本里最常见的 TLD：.com(4921)、.net(658)、.shop(204)、.org(177)、.xyz(174)、.pl(125)、.site(115)、.vn(112)、.pro(111)、.tv(86)、.info(83)、.ru(82)

```
win-prize.ml                                       score=57  恶意URL
you-win.top                                        score=57  恶意URL
tuiskr.com                                         score=0   恶意URL
togethers.tv                                       score=0   恶意URL
vps.atlas101.us.kg                                 score=5   恶意URL
taskerempresascol.co                               score=0   恶意URL
theservice4u.com                                   score=0   恶意URL
verification-process.com                           score=8   恶意URL
taunahi.st                                         score=0   恶意URL
trekworkshop3.com                                  score=0   恶意URL
```

## 5) 误报明细（top 15）

| 域名 | 分数 | 命中规则 |
|---|---|---|
| tmcall.store | 61 | suspicious_tld, typosquatting |
| zcloud.lol | 61 | suspicious_tld, typosquatting |
| jp.walletnest78383369.com | 61 | keywords, typosquatting, dga |

## 6) 真实流量

| 域名 | 分数 | 误报 | 命中规则 |
|---|---|---|---|
| douyin.com | 0 | 否 |  |
| examcrafts.com | 0 | 否 |  |
| game.metaso.cn | 0 | 否 |  |
| hltv.org | 0 | 否 |  |
| deepseek.com | 0 | 否 |  |
| secure-login.faceb00k.tk | 100 | **是** | suspicious_tld, keywords, typosquatting, pattern_library |
| bilibili.com | 0 | 否 |  |
| example.com | 0 | 否 |  |
| pornvideotop.com | 85 | **是** | adult_content |
| videos6.com | 0 | 否 |  |

## 7) 额外评测集（只测召回, 没有对应负样本）

- **IP 直连恶意（http:）**：42853 条，命中 42852（**100.00%**）
- **IP 直连恶意（https:）**：42853 条，命中 1824（**4.26%**）
- **带路径恶意 URL**：17955 条，命中 339（**1.89%**）
