import DOMPurify from 'dompurify';

const STORAGE_KEY = 'security_rate_limits';

const getRateLimitStorage = () => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? JSON.parse(stored) : {};
  } catch {
    return {};
  }
};

const setRateLimitStorage = (data) => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {}
};

export const security = {
  sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    
    let sanitized = DOMPurify.sanitize(input, {
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: []
    });
    
    sanitized = sanitized
      .replace(/<[^>]*>/g, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .replace(/data:/gi, '')
      .replace(/vbscript:/gi, '')
      .trim();
    
    return sanitized;
  },

  sanitizeUsername(username) {
    if (typeof username !== 'string') return '';
    
    return username
      .replace(/[<>"'&;(){}[\]\\\/]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 30);
  },

  sanitizeRoomId(roomId) {
    if (typeof roomId !== 'string') return '';
    
    return roomId
      .replace(/[^a-zA-Z0-9_-]/g, '')
      .slice(0, 50);
  },

  sanitizeMessage(message) {
    if (typeof message !== 'string') return '';
    
    let sanitized = this.sanitizeInput(message);
    sanitized = sanitized.slice(0, 1000);
    
    return sanitized;
  },

  validateUrl(url) {
    if (typeof url !== 'string') return false;
    
    try {
      const parsed = new URL(url);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  },

  checkRateLimit(userId, action, maxRequests = 10, windowMs = 60000) {
    const key = `${userId}:${action}`;
    const now = Date.now();
    
    const storage = getRateLimitStorage();
    
    if (!storage[key]) {
      storage[key] = { count: 1, windowStart: now };
      setRateLimitStorage(storage);
      return { allowed: true, remaining: maxRequests - 1 };
    }
    
    const record = storage[key];
    
    if (now - record.windowStart > windowMs) {
      storage[key] = { count: 1, windowStart: now };
      setRateLimitStorage(storage);
      return { allowed: true, remaining: maxRequests - 1 };
    }
    
    if (record.count >= maxRequests) {
      const retryAfter = Math.ceil((record.windowStart + windowMs - now) / 1000);
      return { allowed: false, remaining: 0, retryAfter };
    }
    
    record.count++;
    setRateLimitStorage(storage);
    return { allowed: true, remaining: maxRequests - record.count };
  },

  resetRateLimit(userId, action) {
    const key = `${userId}:${action}`;
    const storage = getRateLimitStorage();
    delete storage[key];
    setRateLimitStorage(storage);
  },

  cleanExpiredRateLimits(windowMs = 300000) {
    const storage = getRateLimitStorage();
    const now = Date.now();
    
    Object.keys(storage).forEach(key => {
      if (now - storage[key].windowStart > windowMs) {
        delete storage[key];
      }
    });
    
    setRateLimitStorage(storage);
  },

  escapeHtml(text) {
    if (typeof text !== 'string') return '';
    
    const htmlEscapes = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '/': '&#x2F;',
      '`': '&#x60;',
      '=': '&#x3D;'
    };
    
    return text.replace(/[&<>"'`=\/]/g, char => htmlEscapes[char]);
  },

  detectXSSPatterns(input) {
    if (typeof input !== 'string') return false;
    
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript\s*:/gi,
      /on(click|load|error|mouseover|focus|blur|submit|change|input)\s*=/gi,
      /<iframe/gi,
      /<object/gi,
      /<embed/gi,
      /<link\s+.*?href/gi,
      /<meta\s+.*?http-equiv/gi,
      /expression\s*\(/gi,
      /eval\s*\(/gi,
      /document\.(cookie|write|location)/gi,
      /window\.(location|open)/gi,
      /\.innerHTML\s*=/gi,
      /\.outerHTML\s*=/gi,
      /fromCharCode/gi,
      /String\.fromCodePoint/gi,
      /atob\s*\(/gi,
      /btoa\s*\(/gi
    ];
    
    return xssPatterns.some(pattern => pattern.test(input));
  },

  generateSessionId() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
  },

  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
  },

  validateMessageIntegrity(message) {
    if (!message || typeof message !== 'object') return false;
    
    const requiredFields = ['id', 'user', 'original', 'encrypted', 'timestamp'];
    return requiredFields.every(field => message.hasOwnProperty(field));
  },

  isValidTimestamp(timestamp, maxAgeHours = 24) {
    if (typeof timestamp !== 'number') return false;
    
    const now = Date.now();
    const age = now - timestamp;
    const maxAge = maxAgeHours * 60 * 60 * 1000;
    
    return age >= 0 && age <= maxAge;
  }
};

export default security;
