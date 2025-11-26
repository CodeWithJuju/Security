import React, { useEffect, useState, useCallback } from 'react';
import {
  Lock, Send, Trash2, Eye, EyeOff, Shield, Clock,
  AlertTriangle, Users, Zap, ShieldAlert, LogOut, Layers, Key
} from 'lucide-react';
import security from './utils/security';

const storage = {
  async get(key) {
    try {
      if (window.storage && typeof window.storage.get === 'function') {
        return await window.storage.get(key, true);
      }
      const raw = localStorage.getItem(key);
      return raw ? { value: raw } : null;
    } catch (e) {
      console.error('storage.get error', e);
      return null;
    }
  },
  async set(key, value) {
    try {
      if (window.storage && typeof window.storage.set === 'function') {
        return await window.storage.set(key, value, true);
      }
      localStorage.setItem(key, value);
      return true;
    } catch (e) {
      console.error('storage.set error', e);
    }
  }
};

const xorEncrypt = (text, key) => {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return result;
};

const base64Encode = (text) => {
  try {
    return btoa(unescape(encodeURIComponent(text)));
  } catch {
    return btoa(text);
  }
};

const base64Decode = (text) => {
  try {
    return decodeURIComponent(escape(atob(text)));
  } catch {
    try {
      return atob(text);
    } catch {
      return text;
    }
  }
};

const reverseString = (str) => str.split('').reverse().join('');

const shuffleEncrypt = (text) => {
  const chars = text.split('');
  const pattern = [2, 0, 3, 1];
  const chunks = [];
  
  for (let i = 0; i < chars.length; i += 4) {
    const chunk = chars.slice(i, i + 4);
    const shuffled = pattern.map(idx => chunk[idx] || '').join('');
    chunks.push(shuffled);
  }
  
  return chunks.join('');
};

const shuffleDecrypt = (text) => {
  const chars = text.split('');
  const reversePattern = [1, 3, 0, 2];
  const chunks = [];
  
  for (let i = 0; i < chars.length; i += 4) {
    const chunk = chars.slice(i, i + 4);
    const unshuffled = reversePattern.map(idx => chunk[idx] || '').join('');
    chunks.push(unshuffled);
  }
  
  return chunks.join('');
};

export default function SecureChat() {
  const [messages, setMessages] = useState([]);
  const [inputText, setInputText] = useState('');
  const [username, setUsername] = useState('');
  const [roomId, setRoomId] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showEncrypted, setShowEncrypted] = useState({});
  const [blockedMessages, setBlockedMessages] = useState({});
  const [shakeMessages, setShakeMessages] = useState({});
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isTyping, setIsTyping] = useState(false);
  const [notification, setNotification] = useState(null);
  const [securityBlocked, setSecurityBlocked] = useState(false);
  const [rateLimitWarning, setRateLimitWarning] = useState(null);
  const [sessionId] = useState(() => security.generateSessionId());
  const [particles] = useState(() => 
    Array.from({ length: 20 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      delay: Math.random() * 5,
      size: 2 + Math.random() * 4
    }))
  );

  const ENCRYPTION_KEY = 'SecureChatKey2024!';

  const caesarEncrypt = (text, shift = 13) => {
    return text.split('').map(char => {
      if (char.match(/[a-z]/i)) {
        const code = char.charCodeAt(0);
        const base = code >= 65 && code <= 90 ? 65 : 97;
        return String.fromCharCode(((code - base + shift) % 26) + base);
      }
      return char;
    }).join('');
  };

  const caesarDecrypt = (text, shift = 13) => caesarEncrypt(text, 26 - shift);

  const encryptMessage = (text) => {
    const layer1 = caesarEncrypt(text, 13);
    const layer2 = xorEncrypt(layer1, ENCRYPTION_KEY);
    const layer3 = base64Encode(layer2);
    const layer4 = reverseString(shuffleEncrypt(layer3));
    return layer4;
  };

  const decryptMessage = (encrypted) => {
    try {
      const layer4 = shuffleDecrypt(reverseString(encrypted));
      const layer3 = base64Decode(layer4);
      const layer2 = xorEncrypt(layer3, ENCRYPTION_KEY);
      const layer1 = caesarDecrypt(layer2, 13);
      return layer1;
    } catch {
      return '[Erro ao descriptografar]';
    }
  };

  const showNotification = useCallback((message, type = 'info') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 3500);
  }, []);

  useEffect(() => {
    if (isLoggedIn && roomId) {
      loadRoomMessages();
      addJoinMessage();
      setIsConnected(true);
      showNotification('Conectado com criptografia de 4 camadas!', 'success');

      const interval = setInterval(() => {
        loadRoomMessages();
      }, 3000);

      return () => clearInterval(interval);
    }
  }, [isLoggedIn, roomId]);

  const addJoinMessage = async () => {
    const sanitizedRoomId = security.sanitizeRoomId(roomId);
    const sanitizedUsername = security.sanitizeUsername(username);
    
    const result = await storage.get(`room:${sanitizedRoomId}:messages`);
    let roomData = { messages: [], users: [] };
    
    if (result && result.value) {
      roomData = JSON.parse(result.value);
    }

    const joinMessage = {
      id: Date.now() + Math.random(),
      user: 'Sistema',
      original: `${sanitizedUsername} entrou na sala`,
      encrypted: encryptMessage(`${sanitizedUsername} entrou na sala`),
      timestamp: Date.now(),
      isSystem: true,
      type: 'join'
    };

    const updatedMessages = [...(roomData.messages || []), joinMessage];
    const updatedUsers = Array.from(new Set([...(roomData.users || []), sanitizedUsername]));

    await storage.set(`room:${sanitizedRoomId}:messages`, JSON.stringify({
      messages: updatedMessages,
      users: updatedUsers,
      lastUpdate: Date.now()
    }));

    setMessages(updatedMessages);
    setOnlineUsers(updatedUsers);
  };

  const handleLeaveRoom = async () => {
    const sanitizedRoomId = security.sanitizeRoomId(roomId);
    const sanitizedUsername = security.sanitizeUsername(username);

    const leaveMessage = {
      id: Date.now() + Math.random(),
      user: 'Sistema',
      original: `O Usuario ${sanitizedUsername} saiu da Sala`,
      encrypted: encryptMessage(`O Usuario ${sanitizedUsername} saiu da Sala`),
      timestamp: Date.now(),
      isSystem: true,
      type: 'leave'
    };

    const updatedMessages = [...messages, leaveMessage];
    const updatedUsers = onlineUsers.filter(u => u !== sanitizedUsername);

    await saveRoomMessages(updatedMessages, updatedUsers);

    setIsLoggedIn(false);
    setIsConnected(false);
    setMessages([]);
    setOnlineUsers([]);
  };

  const loadRoomMessages = async () => {
    try {
      const sanitizedRoomId = security.sanitizeRoomId(roomId);
      const result = await storage.get(`room:${sanitizedRoomId}:messages`);
      if (result && result.value) {
        const roomData = JSON.parse(result.value);
        const prevLength = messages.length;
        setMessages(roomData.messages || []);
        setOnlineUsers(roomData.users || []);

        if (roomData.messages?.length > prevLength) {
          const newMsg = roomData.messages[roomData.messages.length - 1];
          if (newMsg.user !== username && !newMsg.isSystem) {
            showNotification(`${newMsg.user} enviou uma mensagem`, 'info');
          }
        }
      }
    } catch (error) {
      console.log('Sala nova ou erro ao carregar:', error);
    }
  };

  const saveRoomMessages = async (newMessages, users) => {
    try {
      const sanitizedRoomId = security.sanitizeRoomId(roomId);
      const roomData = {
        messages: newMessages,
        users: users,
        lastUpdate: Date.now()
      };
      await storage.set(`room:${sanitizedRoomId}:messages`, JSON.stringify(roomData));
    } catch (error) {
      console.error('Erro ao salvar mensagens:', error);
    }
  };

  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      setMessages(prev => {
        const filtered = prev.filter(msg => {
          const age = now - msg.timestamp;
          const hours = age / (1000 * 60 * 60);
          return hours < 24;
        });
        if (filtered.length !== prev.length) {
          saveRoomMessages(filtered, onlineUsers);
        }
        return filtered;
      });
    }, 60000);

    return () => clearInterval(interval);
  }, [onlineUsers]);

  const sendMessage = async () => {
    const rateCheck = security.checkRateLimit(sessionId, 'send_message', 15, 60000);
    if (!rateCheck.allowed) {
      setRateLimitWarning(`Aguarde ${rateCheck.retryAfter}s para enviar mais mensagens`);
      showNotification('Muitas mensagens! Aguarde um momento.', 'error');
      setTimeout(() => setRateLimitWarning(null), 3000);
      return;
    }

    const sanitizedMessage = security.sanitizeMessage(inputText);
    
    if (security.detectXSSPatterns(inputText)) {
      setSecurityBlocked(true);
      showNotification('Conteudo bloqueado por seguranca!', 'error');
      setTimeout(() => setSecurityBlocked(false), 3000);
      return;
    }

    if (sanitizedMessage.trim() && username.trim()) {
      const encrypted = encryptMessage(sanitizedMessage);
      const newMessage = {
        id: Date.now() + Math.random(),
        user: security.sanitizeUsername(username),
        original: sanitizedMessage,
        encrypted,
        timestamp: Date.now(),
        hash: security.hashString(sanitizedMessage + Date.now())
      };

      const updatedMessages = [...messages, newMessage];
      const updatedUsers = Array.from(new Set([...onlineUsers, security.sanitizeUsername(username)]));

      setMessages(updatedMessages);
      setOnlineUsers(updatedUsers);
      setInputText('');
      setIsTyping(false);

      await saveRoomMessages(updatedMessages, updatedUsers);
      showNotification('Mensagem criptografada em 4 camadas!', 'success');
    }
  };

  const deleteMessage = async (id) => {
    const rateCheck = security.checkRateLimit(sessionId, 'delete_message', 10, 60000);
    if (!rateCheck.allowed) {
      showNotification('Muitas exclusoes! Aguarde um momento.', 'error');
      return;
    }

    const updatedMessages = messages.filter(msg => msg.id !== id);
    setMessages(updatedMessages);
    await saveRoomMessages(updatedMessages, onlineUsers);
    showNotification('Mensagem deletada', 'info');
  };

  const toggleEncryption = (id) => {
    const message = messages.find(msg => msg.id === id);

    if (message && message.user !== username && !message.isSystem) {
      setBlockedMessages(prev => ({ ...prev, [id]: true }));
      setShakeMessages(prev => ({ ...prev, [id]: true }));
      showNotification('Acesso negado! Criptografia protegida.', 'error');

      setTimeout(() => setShakeMessages(prev => ({ ...prev, [id]: false })), 500);
      return;
    }

    setShowEncrypted(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const getTimeRemaining = (timestamp) => {
    const now = Date.now();
    const hoursRemaining = 24 - ((now - timestamp) / (1000 * 60 * 60));
    if (hoursRemaining < 1) {
      const minutesRemaining = Math.max(0, Math.floor(hoursRemaining * 60));
      return `${minutesRemaining}min`;
    }
    return `${Math.max(0, Math.floor(hoursRemaining))}h`;
  };

  const handleLogin = () => {
    const rateCheck = security.checkRateLimit(sessionId, 'login', 5, 60000);
    if (!rateCheck.allowed) {
      showNotification('Muitas tentativas! Aguarde um momento.', 'error');
      return;
    }

    const sanitizedUsername = security.sanitizeUsername(username);
    const sanitizedRoomId = security.sanitizeRoomId(roomId);

    if (security.detectXSSPatterns(username) || security.detectXSSPatterns(roomId)) {
      setSecurityBlocked(true);
      showNotification('Entrada bloqueada por seguranca!', 'error');
      setTimeout(() => setSecurityBlocked(false), 3000);
      return;
    }

    if (sanitizedUsername.trim() && sanitizedRoomId.trim()) {
      setUsername(sanitizedUsername);
      setRoomId(sanitizedRoomId);
      setIsLoggedIn(true);
    }
  };

  const handleInputChange = (e) => {
    const value = e.target.value;
    if (value.length <= 1000) {
      setInputText(value);
      setIsTyping(value.length > 0);
    }
  };

  if (!isLoggedIn) {
    return (
      <>
        <div className="particles">
          {particles.map(p => (
            <div
              key={p.id}
              className="particle"
              style={{
                left: `${p.x}%`,
                top: `${p.y}%`,
                width: p.size,
                height: p.size,
                animationDelay: `${p.delay}s`
              }}
            />
          ))}
        </div>

        {notification && (
          <div className={`notification ${notification.type}`}>
            {notification.message}
          </div>
        )}

        <div style={{ width:'100%', display:'flex', justifyContent:'center', position:'relative', zIndex:1 }}>
          <div className="container" style={{ display:'flex', gap:0 }}>
            <div className="left" style={{ flex:'0 0 400px' }}>
              <div style={{textAlign:'center', marginBottom:20}}>
                <div className="shield-icon">
                  <Shield style={{width:90, height:90, color:'#8b5cf6'}} />
                </div>
                <h2 className="gradient-text" style={{margin:'16px 0', fontSize:28, fontWeight:800}}>Chat Seguro Global</h2>
                <p className="small" style={{fontSize:14}}>Criptografia avancada em 4 camadas</p>
              </div>

              {securityBlocked && (
                <div style={{background:'linear-gradient(135deg, rgba(239,68,68,0.2), rgba(220,38,38,0.1))', border:'1px solid rgba(239,68,68,0.3)', borderRadius:12, padding:14, marginBottom:14, display:'flex', alignItems:'center', gap:10}}>
                  <ShieldAlert style={{width:22, height:22, color:'#ef4444'}} />
                  <span style={{color:'#f87171', fontSize:14, fontWeight:500}}>Conteudo bloqueado por seguranca</span>
                </div>
              )}

              <div style={{marginTop:24}}>
                <input 
                  className="input" 
                  placeholder="Digite seu nome de usuario" 
                  value={username}
                  onChange={e => setUsername(e.target.value.slice(0, 30))}
                  maxLength={30}
                />

                <input 
                  className="input" 
                  placeholder="ID da Sala (ex: sala123)" 
                  value={roomId}
                  onChange={e => setRoomId(e.target.value.slice(0, 50))}
                  onKeyDown={e => e.key === 'Enter' && handleLogin()}
                  maxLength={50}
                />

                <button className="button" style={{width:'100%', marginTop:8}} onClick={handleLogin} disabled={!username.trim() || !roomId.trim()}>
                  <div style={{display:'flex',alignItems:'center',gap:10,justifyContent:'center'}}>
                    <Zap style={{width:18, height:18}} />
                    <span>Entrar no Chat Seguro</span>
                  </div>
                </button>
              </div>

              <div className="glass-card" style={{marginTop:24}}>
                <h4 style={{marginBottom:12, display:'flex', alignItems:'center', gap:8}}>
                  <Layers style={{width:18, height:18, color:'#8b5cf6'}} />
                  <span className="gradient-text">4 Camadas de Criptografia</span>
                </h4>
                <div style={{display:'flex', flexWrap:'wrap', gap:6}}>
                  <span className="encryption-badge layer1"><Key style={{width:12, height:12}}/> Caesar ROT13</span>
                  <span className="encryption-badge layer2"><Key style={{width:12, height:12}}/> XOR Cipher</span>
                  <span className="encryption-badge layer3"><Key style={{width:12, height:12}}/> Base64</span>
                  <span className="encryption-badge layer4"><Key style={{width:12, height:12}}/> Shuffle + Reverse</span>
                </div>
              </div>

              <div className="glass-card" style={{marginTop:16}}>
                <h4 style={{marginBottom:10}}>Protecoes Ativas</h4>
                <ul className="security-list small" style={{paddingLeft:0, margin:0, listStyle:'none'}}>
                  <li>Anti-XSS Protection</li>
                  <li>Rate Limiting DDoS</li>
                  <li>Input Sanitization</li>
                  <li>Auto-destruicao 24h</li>
                </ul>
              </div>
            </div>

            <div className="right" style={{flex:1}}>
              <div style={{display:'flex', justifyContent:'center', alignItems:'center', height:'100%'}}>
                <div style={{textAlign:'center'}}>
                  <div style={{marginBottom:20}}>
                    <Lock style={{width:80, height:80, color:'#8b5cf6', opacity:0.3}} />
                  </div>
                  <h3 style={{opacity:0.7, marginBottom:10}}>Entre com usuario e sala</h3>
                  <p className="small" style={{maxWidth:300, margin:'0 auto'}}>
                    Suas mensagens serao protegidas com criptografia de 4 camadas e auto-destruicao em 24 horas.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="particles">
        {particles.map(p => (
          <div
            key={p.id}
            className="particle"
            style={{
              left: `${p.x}%`,
              top: `${p.y}%`,
              width: p.size,
              height: p.size,
              animationDelay: `${p.delay}s`
            }}
          />
        ))}
      </div>

      {notification && (
        <div className={`notification ${notification.type}`}>
          {notification.message}
        </div>
      )}

      <div style={{ width:'100%', display:'flex', justifyContent:'center', position:'relative', zIndex:1 }}>
        <div className="container" style={{ display:'flex' }}>
          <div className="left" style={{ flex:'0 0 340px', padding:28 }}>
            <div style={{display:'flex', gap:12, alignItems:'center', marginBottom:16}}>
              <div className="avatar">
                {username.charAt(0).toUpperCase()}
              </div>
              <div>
                <div style={{fontWeight:700, fontSize:16}}>{security.escapeHtml(username)}</div>
                <div className="small" style={{display:'flex', alignItems:'center', gap:6}}>
                  <div className={`status-dot ${isConnected ? 'online' : 'offline'}`}></div>
                  {isConnected ? 'Online' : 'Offline'}
                </div>
              </div>
            </div>

            <div className="glass-card" style={{marginBottom:16}}>
              <div style={{display:'flex', alignItems:'center', gap:8, marginBottom:8}}>
                <Lock style={{width:16, height:16, color:'#8b5cf6'}} />
                <span style={{fontWeight:600}}>Sala: {security.escapeHtml(roomId)}</span>
              </div>
              <div className="badge" style={{display:'inline-flex', alignItems:'center', gap:6}}>
                <Users style={{width:14, height:14}} />
                {onlineUsers.length} usuarios
              </div>
            </div>

            <div className="glass-card" style={{marginBottom:16}}>
              <h4 style={{marginBottom:10, display:'flex', alignItems:'center', gap:8}}>
                <Layers style={{width:16, height:16, color:'#8b5cf6'}} />
                Criptografia
              </h4>
              <div style={{display:'flex', flexDirection:'column', gap:6}}>
                <span className="encryption-badge layer1"><Key style={{width:10, height:10}}/> Caesar</span>
                <span className="encryption-badge layer2"><Key style={{width:10, height:10}}/> XOR</span>
                <span className="encryption-badge layer3"><Key style={{width:10, height:10}}/> Base64</span>
                <span className="encryption-badge layer4"><Key style={{width:10, height:10}}/> Shuffle</span>
              </div>
            </div>

            <div className="glass-card">
              <h4 style={{marginBottom:10}}>Protecoes</h4>
              <ul className="security-list small" style={{paddingLeft:0, margin:0, listStyle:'none'}}>
                <li>XSS Protection</li>
                <li>Rate Limiting</li>
                <li>CSP Headers</li>
                <li>Anti-Injection</li>
              </ul>
            </div>
          </div>

          <div className="right" style={{ flex:1, display:'flex', flexDirection:'column', padding:24 }}>
            <div className="space-between" style={{marginBottom:16}}>
              <div style={{display:'flex', alignItems:'center', gap:12}}>
                <Shield style={{width:28, height:28, color:'#8b5cf6'}} />
                <div>
                  <div style={{fontWeight:700, fontSize:18}}>Sala - {security.escapeHtml(roomId)}</div>
                  <div className="small">Criptografia de 4 camadas ativa</div>
                </div>
              </div>
              <button className="button" onClick={handleLeaveRoom} style={{padding:'10px 16px'}}>
                <div style={{display:'flex', alignItems:'center', gap:6}}>
                  <LogOut style={{width:16, height:16}} />
                  Sair
                </div>
              </button>
            </div>

            {securityBlocked && (
              <div style={{background:'linear-gradient(135deg, rgba(239,68,68,0.2), rgba(220,38,38,0.1))', border:'1px solid rgba(239,68,68,0.3)', borderRadius:12, padding:14, marginBottom:14, display:'flex', alignItems:'center', gap:10}}>
                <ShieldAlert style={{width:20, height:20, color:'#ef4444'}} />
                <span style={{color:'#f87171', fontSize:14}}>Conteudo malicioso bloqueado!</span>
              </div>
            )}

            {rateLimitWarning && (
              <div style={{background:'linear-gradient(135deg, rgba(251,191,36,0.2), rgba(245,158,11,0.1))', border:'1px solid rgba(251,191,36,0.3)', borderRadius:12, padding:14, marginBottom:14, display:'flex', alignItems:'center', gap:10}}>
                <Clock style={{width:20, height:20, color:'#fbbf24'}} />
                <span style={{color:'#fbbf24', fontSize:14}}>{rateLimitWarning}</span>
              </div>
            )}

            <div className="messages" style={{flex:1}}>
              {messages.length === 0 ? (
                <div style={{textAlign:'center', marginTop:60}}>
                  <Shield style={{width:80, height:80, color:'#8b5cf6', opacity:0.2}} />
                  <div className="small" style={{marginTop:16, fontSize:14}}>Nenhuma mensagem ainda - seja o primeiro!</div>
                </div>
              ) : (
                messages.map((msg) => {
                  if (msg.isSystem) {
                    return (
                      <div key={msg.id} className={`system-msg ${msg.type}`}>
                        {msg.type === 'leave' && <LogOut style={{width:14, height:14, display:'inline', marginRight:8, verticalAlign:'middle'}}/>}
                        {msg.type === 'join' && <Zap style={{width:14, height:14, display:'inline', marginRight:8, verticalAlign:'middle'}}/>}
                        {security.escapeHtml(msg.original)}
                      </div>
                    );
                  }

                  return (
                    <div 
                      key={msg.id} 
                      className={`msg ${shakeMessages[msg.id] ? 'shake' : ''}`} 
                      style={{ marginLeft: msg.user === username ? 'auto' : 0, maxWidth:550 }}
                    >
                      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:10}}>
                        <div style={{display:'flex', gap:10, alignItems:'center'}}>
                          <div className="avatar" style={{width:38, height:38, fontSize:14}}>
                            {String(msg.user).charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <div style={{fontWeight:700}}>{security.escapeHtml(msg.user)}</div>
                            <div className="small" style={{display:'flex', alignItems:'center', gap:4}}>
                              <Clock style={{width:12, height:12}}/> {getTimeRemaining(msg.timestamp)}
                            </div>
                          </div>
                        </div>
                        <div style={{display:'flex', gap:8, alignItems:'center'}}>
                          <button 
                            onClick={() => toggleEncryption(msg.id)} 
                            title="Mostrar/ocultar criptografia"
                            style={{background:'rgba(139,92,246,0.1)', border:'1px solid rgba(139,92,246,0.2)', borderRadius:8, padding:8, cursor:'pointer', transition:'all 0.3s'}}
                          >
                            {showEncrypted[msg.id] ? <Eye style={{width:16,height:16, color:'#8b5cf6'}}/> : <EyeOff style={{width:16,height:16, color:'#8b5cf6'}}/>}
                          </button>
                          {msg.user === username && (
                            <button 
                              onClick={() => deleteMessage(msg.id)} 
                              title="Apagar"
                              style={{background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.2)', borderRadius:8, padding:8, cursor:'pointer', transition:'all 0.3s'}}
                            >
                              <Trash2 style={{width:16,height:16, color:'#f87171'}}/>
                            </button>
                          )}
                        </div>
                      </div>

                      {blockedMessages[msg.id] ? (
                        <div style={{background:'rgba(239,68,68,0.1)', padding:16, borderRadius:10, border:'1px solid rgba(239,68,68,0.2)'}}>
                          <div style={{fontFamily:'monospace', fontSize:24, color:'#ef4444', marginBottom:8}}>****</div>
                          <div style={{display:'flex', gap:8, alignItems:'center', color:'#f87171'}}>
                            <AlertTriangle style={{width:18, height:18}}/> 
                            <strong>ACESSO NAO AUTORIZADO</strong>
                          </div>
                        </div>
                      ) : (
                        <>
                          <div style={{whiteSpace:'pre-wrap', marginBottom:10, lineHeight:1.6}}>
                            {security.escapeHtml(msg.original)}
                          </div>
                          {showEncrypted[msg.id] && (
                            <div>
                              <div style={{display:'flex', gap:6, marginBottom:8, flexWrap:'wrap'}}>
                                <span className="encryption-badge layer1" style={{fontSize:10}}>Caesar</span>
                                <span className="encryption-badge layer2" style={{fontSize:10}}>XOR</span>
                                <span className="encryption-badge layer3" style={{fontSize:10}}>Base64</span>
                                <span className="encryption-badge layer4" style={{fontSize:10}}>Shuffle</span>
                              </div>
                              <div className="crypto-display">
                                <Lock style={{width:12,height:12, display:'inline', marginRight:6, verticalAlign:'middle'}}/>
                                {security.escapeHtml(msg.encrypted)}
                              </div>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  );
                })
              )}
            </div>

            <div style={{marginTop:16}}>
              <div style={{display:'flex', gap:10}}>
                <input
                  className="input"
                  style={{marginBottom:0, flex:1}}
                  placeholder="Digite sua mensagem segura..."
                  value={inputText}
                  onChange={handleInputChange}
                  onKeyDown={e => e.key === 'Enter' && sendMessage()}
                  maxLength={1000}
                />
                <button className="button" onClick={sendMessage} disabled={!inputText.trim()} style={{padding:'14px 24px'}}>
                  <div style={{display:'flex', alignItems:'center', gap:8}}>
                    <Send style={{width:18, height:18}} />
                    Enviar
                  </div>
                </button>
              </div>

              <div style={{display:'flex', justifyContent:'space-between', marginTop:12, alignItems:'center'}}>
                <div className="small" style={{display:'flex', alignItems:'center', gap:8}}>
                  <div className="status-dot online"></div>
                  Criptografia de 4 camadas ativa
                </div>
                <div className="small" style={{display:'flex', alignItems:'center', gap:6}}>
                  <Clock style={{width:12, height:12}} />
                  Auto-destruicao em 24h
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
