import bcrypt from 'bcrypt';

// ════════════════════════════════════════════════════════════════════════════
//  CONTENT BOTS / CHANNELS
//  Auto-post fresh content from the internet a few times a day, so the feed
//  always has something. Posts land in the normal `posts` table → they show up
//  in everyone's feed/recommendations automatically.
//
//  Sources used (all free, no API key):
//   - Reddit public JSON (very reliable) for EN channels + memes (images)
//   - RSS feeds for Russian channels
//  Each channel is wrapped in try/catch — a broken source just skips that run.
// ════════════════════════════════════════════════════════════════════════════

// name = @username (channel handle), title = display bio, lang = ru/en.
const CHANNELS = [
  // ─────────────── English (Reddit JSON) ───────────────
  { user: 'world_news', bio: '🌍 World News',            lang: 'en', type: 'reddit', sub: 'worldnews',          images: false },
  { user: 'sports',     bio: '🏅 Sports',                lang: 'en', type: 'reddit', sub: 'sports',             images: false },
  { user: 'football',   bio: '⚽ Football',              lang: 'en', type: 'reddit', sub: 'soccer',             images: false },
  { user: 'fight_club', bio: '🥊 Fights · UFC & Boxing', lang: 'en', type: 'reddit', sub: 'MMA',                images: false },
  { user: 'politics',   bio: '🏛 Politics',              lang: 'en', type: 'reddit', sub: 'worldnews',          images: false },
  { user: 'cinema',     bio: '🎬 Movies & Premieres',    lang: 'en', type: 'reddit', sub: 'movies',            images: false },
  { user: 'music',      bio: '🎵 Music',                 lang: 'en', type: 'reddit', sub: 'Music',             images: false },
  { user: 'tech',       bio: '💻 Tech, IT & Science',    lang: 'en', type: 'reddit', sub: 'technology',        images: false },
  { user: 'science',    bio: '🔬 Science',               lang: 'en', type: 'reddit', sub: 'science',           images: false },
  { user: 'wild',       bio: '🌿 Nature & Animals',      lang: 'en', type: 'reddit', sub: 'NatureIsFuckingLit', images: true  },
  { user: 'cosmos',     bio: '🔭 Space & Astronomy',     lang: 'en', type: 'reddit', sub: 'spaceporn',         images: true  },
  { user: 'history',    bio: '📜 History',               lang: 'en', type: 'reddit', sub: 'history',           images: false },
  { user: 'memes',      bio: '😂 Memes',                 lang: 'en', type: 'reddit', sub: 'memes',             images: true  },

  // ─────────────── Russian (RSS feeds + image subs) ───────────────
  { user: 'novosti',    bio: '🌍 Новости мира',          lang: 'ru', type: 'rss', url: 'https://lenta.ru/rss/news/world' },
  { user: 'politika',   bio: '🏛 Политика',              lang: 'ru', type: 'rss', url: 'https://lenta.ru/rss/news/russia' },
  { user: 'futbol',     bio: '⚽ Футбол',                lang: 'ru', type: 'rss', url: 'https://www.championat.com/rss/news/football/' },
  { user: 'boi',        bio: '🥊 Бои · UFC и бокс',      lang: 'ru', type: 'rss', url: 'https://www.championat.com/rss/news/boxmma/' },
  { user: 'kino',       bio: '🎬 Кино и премьеры',       lang: 'ru', type: 'rss', url: 'https://lenta.ru/rss/news/culture' },
  { user: 'tehno',      bio: '💻 Технологии и наука',    lang: 'ru', type: 'rss', url: 'https://habr.com/ru/rss/news/?fl=ru' },
  { user: 'sport_ru',   bio: '🏅 Спорт',                 lang: 'ru', type: 'rss', url: 'https://www.sports.ru/rss/main.xml' },
  { user: 'priroda',    bio: '🌿 Природа и животные',    lang: 'ru', type: 'reddit', sub: 'NatureIsFuckingLit', images: true },
  { user: 'kosmos',     bio: '🔭 Космос и астрономия',   lang: 'ru', type: 'reddit', sub: 'spaceporn',         images: true },
  { user: 'memy',       bio: '😂 Мемы',                  lang: 'ru', type: 'reddit', sub: 'memes',             images: true },
];

const seen = new Set(); // de-dupe recent posts (in-memory)
function remember(key) {
  seen.add(key);
  if (seen.size > 400) seen.clear();
}
const pick = (a) => a[Math.floor(Math.random() * a.length)];

// ─── Ensure bot accounts exist; returns { username: id } ─────────────────────
export async function ensureBots(supabase) {
  const map = {};
  for (const ch of CHANNELS) {
    try {
      const { data: existing } = await supabase
        .from('users').select('id').eq('username', ch.user);
      if (existing && existing.length > 0) { map[ch.user] = existing[0].id; continue; }
      const pw = await bcrypt.hash(Math.random().toString(36) + Date.now(), 10);
      const base = {
        username: ch.user,
        email: `${ch.user}@bots.local`,
        password_hash: pw,
        bio: ch.bio,
        followers_count: 0,
        following_count: 0,
      };
      // Try with verified flag; if that column doesn't exist yet, retry without.
      let { data, error } = await supabase
        .from('users').insert([{ ...base, is_verified: true }]).select('id').single();
      if (error) {
        ({ data, error } = await supabase
          .from('users').insert([base]).select('id').single());
      }
      if (!error && data) map[ch.user] = data.id;
    } catch (_) {}
  }
  return map;
}

// ─── Fetchers ────────────────────────────────────────────────────────────────
const UA = { 'User-Agent': 'sigma-social-bot/1.0' };

function decodeHtmlEntities(url) {
  return (url || '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"');
}

function extractRedditImage(p) {
  // 1) Direct image post
  if (p.post_hint === 'image' || /\.(jpg|jpeg|png|gif)(\?.*)?$/i.test(p.url || '')) {
    return decodeHtmlEntities(p.url);
  }
  // 2) preview.images[0].source.url
  try {
    const src = p.preview?.images?.[0]?.source?.url;
    if (src) return decodeHtmlEntities(src);
  } catch (_) {}
  // 3) thumbnail (must be a real URL ending in image ext)
  if (p.thumbnail && /^https?:\/\/.+\.(jpg|jpeg|png|gif)/i.test(p.thumbnail)) {
    return decodeHtmlEntities(p.thumbnail);
  }
  return null;
}

async function fetchReddit(sub, imagesOnly) {
  const r = await fetch(`https://www.reddit.com/r/${sub}/top.json?t=day&limit=25`, { headers: UA });
  const j = await r.json();
  const posts = (j?.data?.children || []).map((c) => c.data).filter(Boolean).filter((p) => !p.over_18);
  if (imagesOnly) {
    return posts
      .filter((p) => p.post_hint === 'image' || /\.(jpg|jpeg|png|gif)$/i.test(p.url || ''))
      .map((p) => ({ title: p.title, image: decodeHtmlEntities(p.url) }));
  }
  // For non-image channels: extract image if available, content = title only (no link)
  return posts.map((p) => ({
    title: p.title,
    image: extractRedditImage(p),
  }));
}

function clean(s) {
  return (s || '')
    .replace(/<!\[CDATA\[|\]\]>/g, '')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ')
    .trim();
}

function extractRSSImage(block) {
  // <enclosure url="...">
  const enc = block.match(/<enclosure[^>]+url=["']([^"']+)["']/i);
  if (enc && enc[1]) return clean(enc[1]);
  // <media:content url="...">
  const media = block.match(/<media:content[^>]+url=["']([^"']+)["']/i);
  if (media && media[1]) return clean(media[1]);
  return null;
}

async function fetchRSS(url) {
  const r = await fetch(url, { headers: UA });
  const xml = await r.text();
  const items = [];
  for (const block of xml.split(/<item[ >]/i).slice(1, 20)) {
    const title = (block.match(/<title>([\s\S]*?)<\/title>/i) || [])[1] || '';
    const t = clean(title);
    if (t) items.push({ title: t, image: extractRSSImage(block) });
  }
  return items;
}

// ─── Run all channels: post one fresh item each ──────────────────────────────
export async function runBots(supabase) {
  const bots = await ensureBots(supabase);
  let posted = 0;
  for (const ch of CHANNELS) {
    const botId = bots[ch.user];
    if (!botId) continue;
    try {
      let content = '';
      let image = null;
      if (ch.type === 'reddit') {
        const items = await fetchReddit(ch.sub, ch.images);
        if (!items.length) continue;
        const it = pick(items);
        content = it.title || '';
        image = it.image || null;
      } else {
        const items = await fetchRSS(ch.url);
        if (!items.length) continue;
        const it = pick(items);
        content = it.title || '';
        image = it.image || null;
      }
      if (!content && !image) continue;
      const key = ch.user + '|' + (image || content).slice(0, 120);
      if (seen.has(key)) continue;
      remember(key);
      await supabase.from('posts').insert([{
        user_id: botId, content, image_url: image || null, likes_count: 0,
      }]);
      // Notify followers of this channel
      try {
        const { data: followers } = await supabase.from('follows').select('follower_id').eq('following_id', botId);
        if (followers && followers.length > 0) {
          const notifs = followers.map(f => ({
            user_id: f.follower_id,
            from_user_id: botId,
            type: 'channel_post',
            message: `${ch.bio}: ${(content || '').slice(0, 60)}`,
            is_read: false,
          }));
          await supabase.from('notifications').insert(notifs);
        }
      } catch (_) {}
      posted++;
    } catch (_) { /* skip channel on error */ }
  }
  return posted;
}
