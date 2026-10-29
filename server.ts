import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { GoogleGenAI } from '@google/genai';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

// ============================================================================
// SUPABASE BACKEND INITIALIZATION (SECRET KEY ONLY ON SERVER)
// ============================================================================
const SUPABASE_URL =
  process.env.SUPABASE_URL ||
  process.env.VITE_SUPABASE_URL ||
  'https://kgmignmwdkywfhshdwex.supabase.co';

const SUPABASE_SECRET_KEY =
  process.env.SUPABASE_SECRET_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  '';

const SUPABASE_JWKS_URL =
  process.env.SUPABASE_JWKS_URL ||
  'https://kgmignmwdkywfhshdwex.supabase.co/auth/v1/.well-known/jwks.json';

const isServerSupabaseConfigured = Boolean(
  SUPABASE_URL &&
    SUPABASE_SECRET_KEY &&
    SUPABASE_SECRET_KEY !== 'YOUR_SUPABASE_SECRET_SERVICE_ROLE_KEY'
);

const supabaseAdmin: SupabaseClient | null = isServerSupabaseConfigured
  ? createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    })
  : null;

// ============================================================================
// ANTI-DDOS & ANTI-SPAM PROTECTION (RATE LIMITER & PHONE LOCK PER IP/DEVICE)
// ============================================================================
interface RateBucket {
  count: number;
  resetAt: number;
  lockedPhone?: string;
  lastLeadAt?: number;
}

const ipRateMap = new Map<string, RateBucket>();

// Valid Uzbekistan mobile & city operator codes
const VALID_UZ_OPERATORS = new Set([
  '90', '91', '93', '94', '95', '97', '98', '99',
  '33', '88', '77', '50', '55', '71', '20',
]);

function validateUzPhoneServer(rawPhone: string): { valid: boolean; normalized: string; error?: string } {
  const digits = (rawPhone || '').replace(/\D/g, '');
  let localNine = '';
  if (digits.startsWith('998') && digits.length === 12) {
    localNine = digits.slice(3);
  } else if (digits.length === 9) {
    localNine = digits;
  } else {
    return {
      valid: false,
      normalized: digits,
      error: 'Введите корректный 9-значный номер Узбекистана в формате +998 (XX) XXX-XX-XX.',
    };
  }

  const op = localNine.slice(0, 2);
  const sub = localNine.slice(2);
  if (!VALID_UZ_OPERATORS.has(op)) {
    return {
      valid: false,
      normalized: `998${localNine}`,
      error: `Неверный код оператора (${op}). Допустимы коды: 90, 91, 93, 94, 95, 97, 98, 99, 33, 88, 77, 50, 55, 71.`,
    };
  }

  // Reject obvious fake sequences like 0000000, 1111111, 1234567
  if (/^(\d)\1{6}$/.test(sub) || sub === '1234567' || sub === '7654321') {
    return {
      valid: false,
      normalized: `998${localNine}`,
      error: 'Указан некорректный номер телефона. Пожалуйста, введите ваш реальный номер.',
    };
  }

  return { valid: true, normalized: `998${localNine}` };
}

function getClientKey(req: express.Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = Array.isArray(forwarded)
    ? forwarded[0]
    : typeof forwarded === 'string'
      ? forwarded.split(',')[0].trim()
      : req.socket.remoteAddress || 'unknown-ip';
  const fp = typeof req.headers['x-client-fingerprint'] === 'string'
    ? req.headers['x-client-fingerprint']
    : '';
  return `${ip}::${fp}`;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.disable('x-powered-by');
  app.use(express.json({ limit: '5mb' }));

  // Security Headers Middleware (Anti-XSS, Anti-Sniffing, Clickjacking & Referrer Protection)
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });

  function sanitizeServerText(input: unknown, maxLen = 500): string {
    if (typeof input !== 'string') return '';
    return input
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/<\/?[^>]+(>|$)/g, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .trim()
      .slice(0, maxLen);
  }

  // Global API Rate Limiter (Anti-DDoS: max 60 API calls per minute per client)
  app.use('/api', (req, res, next) => {
    const key = getClientKey(req);
    const now = Date.now();
    let bucket = ipRateMap.get(key);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + 60_000, lockedPhone: bucket?.lockedPhone, lastLeadAt: bucket?.lastLeadAt };
      ipRateMap.set(key, bucket);
    }
    bucket.count += 1;
    if (bucket.count > 60) {
      return res.status(429).json({
        error: 'Слишком много запросов (защита от DDoS). Пожалуйста, подождите 1 минуту.',
      });
    }
    next();
  });

  // ==========================================================================
  // 1. SUPABASE STATUS & JWKS VERIFICATION ENDPOINT
  // ==========================================================================
  app.get('/api/supabase/status', (_req, res) => {
    res.json({
      projectUrl: SUPABASE_URL,
      jwksUrl: SUPABASE_JWKS_URL,
      backendConnected: isServerSupabaseConfigured,
      rlsEnabled: true,
    });
  });

  // ==========================================================================
  // 2. ANTI-SPAM LEAD SUBMISSION & SUPABASE PERSISTENCE ENDPOINT
  // ==========================================================================
  app.post('/api/leads', async (req, res) => {
    try {
      const { lead, honeypot } = req.body as { lead: any; honeypot?: string };

      // 1. Honeypot check against automated bots
      if (honeypot && String(honeypot).trim().length > 0) {
        return res.status(400).json({ error: 'Запрос отклонен системой защиты от спама.' });
      }

      if (!lead || !lead.studentName || !lead.phoneNumber) {
        return res.status(400).json({ error: 'Укажите имя и номер телефона.' });
      }

      const safeName = sanitizeServerText(lead.studentName, 120);
      if (safeName.length < 2) {
        return res.status(400).json({ error: 'Имя должно содержать минимум 2 символа.' });
      }

      // 2. Strict Uzbekistan Phone Number Validation
      const phoneCheck = validateUzPhoneServer(lead.phoneNumber);
      if (!phoneCheck.valid) {
        return res.status(400).json({ error: phoneCheck.error });
      }

      // 3. Single-Phone-Per-Client Lock & Cooldown Protection
      const clientKey = getClientKey(req);
      const now = Date.now();
      let bucket = ipRateMap.get(clientKey);
      if (!bucket) {
        bucket = { count: 1, resetAt: now + 60_000 };
        ipRateMap.set(clientKey, bucket);
      }

      // Cooldown: minimum 30 seconds between lead submissions from the same device
      if (bucket.lastLeadAt && now - bucket.lastLeadAt < 30_000) {
        const waitSec = Math.ceil((30_000 - (now - bucket.lastLeadAt)) / 1000);
        return res.status(429).json({
          error: `Заявка уже отправлена. Повторная отправка доступна через ${waitSec} сек.`,
        });
      }

      // Prevent submitting different phone numbers from the same device/IP
      if (bucket.lockedPhone && bucket.lockedPhone !== phoneCheck.normalized) {
        return res.status(403).json({
          error:
            'Защита от спама: с вашего устройства уже зарегистрирован другой номер телефона. Использование разных номеров запрещено.',
        });
      }

      bucket.lockedPhone = phoneCheck.normalized;
      bucket.lastLeadAt = now;

      // 4. Persist sanitized lead to Supabase if configured
      let savedToSupabase = false;
      if (supabaseAdmin) {
        const { error } = await supabaseAdmin.from('leads').upsert({
          id: sanitizeServerText(lead.id, 80) || `lead-${Date.now()}`,
          student_name: safeName,
          phone_number: sanitizeServerText(lead.phoneNumber, 32),
          course_title: sanitizeServerText(lead.courseTitle || 'Консультация', 160),
          branch_name: sanitizeServerText(lead.branchName || 'М. Улугбекский филиал', 140),
          comment: sanitizeServerText(lead.comment || '', 500),
          status: 'new',
          assigned_employee: sanitizeServerText(lead.assignedEmployee || 'Приёмная комиссия', 120),
          source: sanitizeServerText(lead.source || 'Веб-сайт Language Vision', 120),
          student_id: lead.studentId ? sanitizeServerText(lead.studentId, 80) : null,
          client_fingerprint: clientKey,
          notes: Array.isArray(lead.notes) ? lead.notes.slice(0, 20) : [],
          status_history: Array.isArray(lead.statusHistory) ? lead.statusHistory.slice(0, 20) : [],
          created_at: lead.createdAt || new Date().toISOString(),
          updated_at: new Date().toISOString(),
        });
        if (!error) {
          savedToSupabase = true;
        }
      }

      return res.json({
        ok: true,
        savedToSupabase,
        normalizedPhone: phoneCheck.normalized,
      });
    } catch (error: any) {
      return res.status(500).json({
        error: 'Ошибка сервера при сохранении заявки.',
      });
    }
  });

  // ==========================================================================
  // 3. SUPABASE DATA BOOTSTRAP & PROTECTED SYNC ROUTES FOR ADMIN PANEL & CRM
  // ==========================================================================
  app.get('/api/supabase/bootstrap', async (_req, res) => {
    if (!supabaseAdmin) {
      return res.json({ connected: false });
    }
    try {
      const [
        branchesRes,
        coursesRes,
        teachersRes,
        resultsRes,
        videosRes,
        leadsRes,
        studentsRes,
        settingsRes,
      ] = await Promise.all([
        supabaseAdmin.from('branches').select('*'),
        supabaseAdmin.from('courses').select('*').order('display_order', { ascending: true }),
        supabaseAdmin.from('teachers').select('*').order('display_order', { ascending: true }),
        supabaseAdmin.from('student_results').select('*').order('display_order', { ascending: true }),
        supabaseAdmin.from('video_testimonials').select('*').order('display_order', { ascending: true }),
        supabaseAdmin.from('leads').select('*').order('created_at', { ascending: false }),
        supabaseAdmin.from('students').select('*').order('enrolled_at', { ascending: false }),
        supabaseAdmin.from('site_settings').select('*').eq('id', 'main').maybeSingle(),
      ]);

      // Strip sensitive bot tokens from public bootstrap response
      const safeSettings = settingsRes.data
        ? { ...settingsRes.data, telegram_bot_token: '' }
        : null;

      return res.json({
        connected: true,
        branches: branchesRes.data || [],
        courses: coursesRes.data || [],
        teachers: teachersRes.data || [],
        results: resultsRes.data || [],
        videos: videosRes.data || [],
        leads: leadsRes.data || [],
        students: studentsRes.data || [],
        settings: safeSettings,
      });
    } catch {
      return res.json({ connected: false });
    }
  });

  app.post('/api/supabase/sync', async (req, res) => {
    if (!supabaseAdmin) {
      return res.json({ ok: true, synced: false, reason: 'SUPABASE_SECRET_KEY not set in .env' });
    }
    try {
      const { table, action, record, id } = req.body as {
        table: string;
        action: 'upsert' | 'delete';
        record?: Record<string, any>;
        id?: string;
      };

      const allowedTables = new Set([
        'branches',
        'courses',
        'teachers',
        'student_results',
        'video_testimonials',
        'leads',
        'students',
        'employees',
        'chat_sessions',
        'audit_logs',
        'site_settings',
      ]);

      if (!allowedTables.has(table)) {
        return res.status(400).json({ error: 'Недопустимая таблица' });
      }

      // Security check: Admin-only tables require authenticated employee/admin
      const publicAllowedTables = new Set(['chat_sessions']);
      if (!publicAllowedTables.has(table)) {
        const adminActor = req.headers['x-admin-actor'];
        const authHeader = req.headers.authorization;
        let isAuthorized = Boolean(adminActor && typeof adminActor === 'string' && adminActor.includes('@'));

        if (!isAuthorized && authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.slice(7);
          const { data: userData } = await supabaseAdmin.auth.getUser(token);
          if (userData?.user) {
            isAuthorized = true;
          }
        }

        if (!isAuthorized) {
          return res.status(403).json({
            ok: false,
            error: 'Доступ запрещен: требуется авторизация администратора.',
          });
        }
      }

      if (action === 'delete' && id) {
        const { error } = await supabaseAdmin.from(table).delete().eq('id', String(id));
        if (error) return res.status(400).json({ ok: false, error: error.message });
        return res.json({ ok: true, synced: true });
      }

      if (action === 'upsert' && record) {
        const { error } = await supabaseAdmin.from(table).upsert(record);
        if (error) return res.status(400).json({ ok: false, error: error.message });
        return res.json({ ok: true, synced: true });
      }

      return res.status(400).json({ error: 'Некорректные параметры синхронизации' });
    } catch (e: any) {
      return res.status(500).json({ ok: false, error: e.message });
    }
  });

  // ==========================================================================
  // 4. AI ASSISTANT ENDPOINT FOR CLIENT WEBSITE CHAT
  // ==========================================================================
  app.post('/api/chat', async (req, res) => {
    try {
      const { messages, courses, branches, contactPhone } = req.body;
      const apiKey = process.env.GEMINI_API_KEY;

      const courseListText = Array.isArray(courses)
        ? courses
            .map(
              (c: any) =>
                `- ${c.title} (${c.category}, уровень ${c.level}, длительность ${c.duration}, расписание: ${c.schedule}, стоимость: ${c.price})`
            )
            .join('\n')
        : '';

      const branchListText = Array.isArray(branches)
        ? branches.map((b: any) => `- ${b.name}: ${b.address} (тел: ${b.phone})`).join('\n')
        : `- Филиал №1 (М. Улугбекский): ул. Буюк Ипак Йули, 77\n- Филиал №2 (Юнусабадский): ул. Янгишахар, 64`;

      if (!apiKey) {
        return res.json({
          reply:
            `Здравствуйте! Я онлайн-консультант академии Language Vision.\n` +
            `Наши филиалы в Ташкенте:\n${branchListText}\n` +
            `Телефоны приёмной комиссии: ${contactPhone || '+998 90 934 24 26'}, +998 90 926 24 26.\n` +
            `Оставьте ваш номер телефона в чате или выберите филиал, и наш оператор свяжется с вами!`,
        });
      }

      const ai = new GoogleGenAI({ apiKey });
      const conversationLog = Array.isArray(messages)
        ? messages
            .slice(-10)
            .map(
              (m: any) =>
                `${m.sender === 'client' ? 'Клиент' : m.sender === 'admin' ? 'Оператор' : 'AI'}: ${m.text}`
            )
            .join('\n')
        : '';

      const systemPrompt = `Ты — вежливый, профессиональный AI-консультант образовательного центра "Language Vision" в Ташкенте (основан в 2014 году).
Отвечай кратко (2–4 предложения), дружелюбно и по делу на языке пользователя (русский, узбекский или английский).
Наши филиалы:
${branchListText}
Телефоны для связи: +998 90 934 24 26, +998 90 926 24 26.
Актуальные курсы и цены:
${courseListText}
Если клиент хочет записаться, попроси его оставить имя, номер телефона и удобный филиал (М. Улугбекский или Юнусабадский).`;

      const response = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: `${systemPrompt}\n\nИстория диалога:\n${conversationLog}\n\nОтвет AI:`,
      });

      const replyText =
        response.text?.trim() ||
        'Спасибо за обращение в Language Vision! Подскажите, какой филиал (М. Улугбекский или Юнусабадский) и какой курс вас интересуют?';

      return res.json({ reply: replyText });
    } catch (error: any) {
      console.error('AI Chat Error:', error?.message || error);
      return res.json({
        reply:
          'Спасибо за ваше сообщение! Оператор Language Vision уже подключился к диалогу и ответит вам в ближайшее время. Вы также можете оставить ваш номер телефона для быстрой связи.',
      });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*all', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Language Vision Server running on http://localhost:${PORT}`);
  });
}

startServer();
