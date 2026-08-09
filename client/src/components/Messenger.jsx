import { useEffect, useMemo, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import { API_BASE, apiFetch } from '../lib/api';
import {
  getOrCreateIdentity,
  deriveSharedKey,
  encryptWithKey,
  decryptWithKey,
  fileToDataUrl
} from '../lib/crypto';

const EMOJIS = [
  '😀', '😁', '😂', '🤣', '😊', '😍', '😘', '😉', '😎', '🤔',
  '😢', '😭', '😡', '😱', '😴', '🙄', '😅', '🥳', '🤗', '🤝',
  '👍', '👎', '👏', '🙏', '💪', '👌', '✌️', '🤞', '👋', '🤙',
  '❤️', '🔥', '✨', '🎉', '💯', '⚡', '✅', '❌', '⭐', '☕'
];

function formatLastSeen(value) {
  if (!value) return 'Never';
  return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}

function initials(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  const a = parts[0]?.[0] || 'U';
  const b = parts[1]?.[0] || parts[0]?.[1] || 'X';
  return (a + b).toUpperCase();
}

function formatFileSize(bytes) {
  if (!bytes && bytes !== 0) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function safeParse(json) {
  try {
    return JSON.parse(json);
  } catch {
    return { kind: 'text', text: json };
  }
}

function fingerprintJwk(jwk) {
  if (!jwk) return '';
  return `${jwk.x || ''}.${jwk.y || ''}`;
}

export default function Messenger({ token, currentUser, onLogout }) {
  const socketRef = useRef(null);
  const inactivityRef = useRef(null);
  const typingTimeoutRef = useRef(null);
  const scrollRef = useRef(null);
  const pcRef = useRef(null);
  const localStreamRef = useRef(null);
  const remoteAudioRef = useRef(null);
  const pendingCallPeerRef = useRef(null);
  const pendingCallIdRef = useRef(null);
  const selectedIdRef = useRef(null);
  const mobileChatOpenRef = useRef(false);
  const isMobileRef = useRef(window.innerWidth <= 768);
  const identityRef = useRef(null);
  const sharedKeysRef = useRef(new Map()); // peerId -> { fp, key }
  const contactsRef = useRef([]);
  const messagesByPeerRef = useRef(new Map()); // cache decrypted msgs per peer id so switching contacts is instant

  const [contacts, setContacts] = useState([]);
  const [socketReady, setSocketReady] = useState(false);
  const [selectedId, setSelectedId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [composer, setComposer] = useState('');
  const [loadingChat, setLoadingChat] = useState(false);
  const [typingUserId, setTypingUserId] = useState(null);
  const [callState, setCallState] = useState(null);
  const [callNotice, setCallNotice] = useState('');
  const [error, setError] = useState('');
  const [replyTarget, setReplyTarget] = useState(null);
  const [editingMessage, setEditingMessage] = useState(null);
  const [activeMenuId, setActiveMenuId] = useState(null);
  const [showEmoji, setShowEmoji] = useState(false);
  const [mobileChatOpen, setMobileChatOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 768);
  const [viewingImage, setViewingImage] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);

  const selectedContact = useMemo(
    () => contacts.find((u) => u.id === selectedId) || null,
    [contacts, selectedId]
  );

  useEffect(() => {
    selectedIdRef.current = selectedId;
  }, [selectedId]);

  useEffect(() => {
    mobileChatOpenRef.current = mobileChatOpen;
  }, [mobileChatOpen]);

  useEffect(() => {
    isMobileRef.current = isMobile;
  }, [isMobile]);

  const isChatActive = (peerId) => {
    if (selectedIdRef.current !== peerId) return false;
    if (isMobileRef.current && !mobileChatOpenRef.current) return false;
    return true;
  };

  useEffect(() => {
    contactsRef.current = contacts;
  }, [contacts]);

  // ---- Per-peer key derivation (ECDH). Private key never leaves this device. ----
  const getSharedKeyFor = async (peerId) => {
    const contact = contactsRef.current.find((c) => c.id === peerId);
    if (!contact?.publicKey || !identityRef.current) return null;
    const fp = fingerprintJwk(contact.publicKey);
    const cached = sharedKeysRef.current.get(peerId);
    if (cached && cached.fp === fp) return cached.key;
    const key = await deriveSharedKey(identityRef.current.privateKey, contact.publicKey);
    sharedKeysRef.current.set(peerId, { fp, key });
    return key;
  };

  const encryptFor = async (peerId, plainObj) => {
    let key = await getSharedKeyFor(peerId);
    if (!key) {
      await refreshContacts();
      key = await getSharedKeyFor(peerId);
    }
    if (!key) throw new Error("Can't encrypt yet — waiting for this contact's key.");
    return encryptWithKey(key, JSON.stringify(plainObj));
  };

  const decryptFrom = async (peerId, encryptedPayload, iv) => {
    const key = await getSharedKeyFor(peerId);
    if (!key) throw new Error('no-key');
    return safeParse(await decryptWithKey(key, encryptedPayload, iv));
  };

  const publishPublicKey = async () => {
    if (!identityRef.current) return;
    try {
      await apiFetch('/keys', { token, method: 'POST', body: { publicKey: identityRef.current.publicJwk } });
    } catch { }
  };

  const refreshContacts = async () => {
    const data = await apiFetch('/contacts', { token });
    setContacts(data.contacts || []);
  };

  const loadChat = async (userId) => {
    if (!userId) return;
    const cached = messagesByPeerRef.current.get(userId);
    if (cached) setMessages(cached);
    setLoadingChat(!cached);
    try {
      const data = await apiFetch(`/conversations/${userId}`, { token });
      const decrypted = await Promise.all((data.messages || []).map(async (msg) => {
        let payload = { kind: msg.type || 'text', text: '' };
        try {
          payload = await decryptFrom(msg.fromId === currentUser.id ? msg.toId : msg.fromId, msg.encryptedPayload, msg.iv);
        } catch {
          payload = { kind: msg.type || 'text', text: '[unable to decrypt]' };
        }
        const isFile = payload.kind === 'photo' || payload.kind === 'document';
        return {
          ...msg,
          mine: msg.fromId === currentUser.id,
          content: isFile ? payload.dataUrl : payload.text,
          payloadKind: payload.kind || msg.type || 'text',
          fileName: payload.name || msg.fileName || null,
          mimeType: payload.mimeType || msg.mimeType || null,
          fileSize: payload.size || null,
          replyTo: payload.replyTo || null
        };
      }));
      setMessages((prev) => {
        const base = prev.length && prev[0] && (prev[0].fromId === userId || prev[0].toId === userId) ? prev : (cached || []);
        const map = new Map();
        [...decrypted, ...base].forEach((m) => map.set(m.id, m));
        const merged = Array.from(map.values()).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
        messagesByPeerRef.current.set(userId, merged);
        return merged;
      });
      if (socketRef.current) {
        socketRef.current.emit('message:seen', {
          otherId: userId,
          messageIds: decrypted.filter((m) => !m.mine).map((m) => m.id)
        });
      }
      setContacts((prev) => prev.map((u) => (u.id === userId ? { ...u, unreadCount: 0 } : u)));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoadingChat(false);
    }
  };

  const logout = async () => {
    try {
      await apiFetch('/logout', { token, method: 'POST' });
    } catch { }
    if (socketRef.current) {
      socketRef.current.emit('logout');
      socketRef.current.disconnect();
      socketRef.current = null;
    }
    setSocketReady(false);
    cleanupCall();
    onLogout();
  };

  const cleanupCall = () => {
    if (pcRef.current) {
      pcRef.current.ontrack = null;
      pcRef.current.onicecandidate = null;
      pcRef.current.close();
      pcRef.current = null;
    }
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach((track) => track.stop());
      localStreamRef.current = null;
    }
    if (remoteAudioRef.current) {
      remoteAudioRef.current.srcObject = null;
    }
    pendingCallPeerRef.current = null;
    pendingCallIdRef.current = null;
    setCallState(null);
    setCallNotice('');
  };

  const endCall = () => {
    const peerId = pendingCallPeerRef.current;
    const callId = pendingCallIdRef.current;
    if (socketRef.current && peerId && callId) {
      socketRef.current.emit('call:end', { toId: peerId, callId });
    }
    cleanupCall();
  };

  const ensurePeerConnection = async (peerId) => {
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: ['stun:stun.l.google.com:19302'] }]
    });

    pc.onicecandidate = (event) => {
      if (event.candidate && socketRef.current && peerId) {
        socketRef.current.emit('call:signal', {
          toId: peerId,
          data: { candidate: event.candidate }
        });
      }
    };

    pc.ontrack = (event) => {
      if (remoteAudioRef.current) {
        remoteAudioRef.current.srcObject = event.streams[0];
      }
    };

    const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    localStreamRef.current = stream;
    stream.getTracks().forEach((track) => pc.addTrack(track, stream));

    pcRef.current = pc;
    pendingCallPeerRef.current = peerId;
    return pc;
  };

  const startOutgoingCall = async (contact) => {
    if (!contact || callState) return;
    const callId = crypto.randomUUID();
    pendingCallPeerRef.current = contact.id;
    pendingCallIdRef.current = callId;
    setCallNotice(`Calling ${contact.displayName}...`);
    setCallState({ mode: 'outgoing', peerId: contact.id, peerName: contact.displayName, callId });
    socketRef.current?.emit('call:initiate', { toId: contact.id, callId });
  };

  const acceptIncomingCall = async (incoming) => {
    try {
      pendingCallPeerRef.current = incoming.fromId;
      pendingCallIdRef.current = incoming.callId;
      setCallNotice(`Connected with ${incoming.fromName}`);
      setCallState({ mode: 'active', peerId: incoming.fromId, peerName: incoming.fromName, callId: incoming.callId });
      socketRef.current?.emit('call:accept', { callId: incoming.callId, toId: incoming.fromId });
      await ensurePeerConnection(incoming.fromId);
    } catch (e) {
      setCallNotice(e.message);
      cleanupCall();
    }
  };

  const rejectIncomingCall = (incoming) => {
    socketRef.current?.emit('call:reject', { callId: incoming.callId, toId: incoming.fromId });
    cleanupCall();
  };

  // ---- Bootstrap identity + socket ----
  useEffect(() => {
    let mounted = true;

    (async () => {
      identityRef.current = await getOrCreateIdentity(currentUser.username);
      await publishPublicKey();
      if (mounted) await refreshContacts();
    })();

    const socket = io(API_BASE, {
      auth: { token }
    });
    socketRef.current = socket;

    socket.on('connect', () => {
      if (!mounted) return;
      setError('');
      setSocketReady(true);
      publishPublicKey();
      refreshContacts();
    });

    socket.on('contacts:list', ({ contacts: nextContacts }) => {
      if (mounted) setContacts(nextContacts || []);
    });

    socket.on('presence:update', ({ userId, online, lastSeen, publicKey }) => {
      setContacts((prev) => prev.map((u) => (u.id === userId ? { ...u, online, lastSeen, ...(publicKey ? { publicKey } : {}) } : u)));
    });

    socket.on('message:deliver', async (msg) => {
      try {
        const payload = await decryptFrom(msg.fromId, msg.encryptedPayload, msg.iv);
        const isFile = payload.kind === 'photo' || payload.kind === 'document';
        const content = isFile ? payload.dataUrl : payload.text;
        const next = {
          ...msg,
          mine: false,
          content,
          payloadKind: payload.kind || msg.type || 'text',
          fileName: payload.name || msg.fileName || null,
          mimeType: payload.mimeType || msg.mimeType || null,
          fileSize: payload.size || null,
          replyTo: payload.replyTo || null
        };
        const bucket = messagesByPeerRef.current.get(msg.fromId) || [];
        messagesByPeerRef.current.set(msg.fromId, [...bucket, next]);
        if (isChatActive(msg.fromId)) {
          setMessages((prev) => [...prev, next]);
          socket.emit('message:seen', { otherId: msg.fromId });
        } else {
          setContacts((prev) =>
            prev.map((u) => (u.id === msg.fromId ? { ...u, unreadCount: (u.unreadCount || 0) + 1 } : u))
          );
        }
      } catch (e) {
        console.error(e);
      }
      refreshContacts();
    });

    socket.on('message:status', ({ withUserId, seenMessageIds = [], seen }) => {
      if (!seen && !seenMessageIds.length) return;
      const updater = (prev) => prev.map((m) =>
        m.mine && (seenMessageIds.includes(m.id) || seen) ? { ...m, seenAt: new Date().toISOString() } : m
      );
      const bucket = messagesByPeerRef.current.get(withUserId);
      if (bucket) messagesByPeerRef.current.set(withUserId, updater(bucket));
      if (selectedIdRef.current === withUserId) setMessages(updater);
    });

    socket.on('message:edited', async ({ messageId, fromId, encryptedPayload, iv }) => {
      try {
        const payload = await decryptFrom(fromId, encryptedPayload, iv);
        const content = payload.kind === 'photo' ? payload.dataUrl : payload.text;
        const apply = (prev) => prev.map((m) => (m.id === messageId ? { ...m, content, edited: true } : m));
        const bucket = messagesByPeerRef.current.get(fromId);
        if (bucket) messagesByPeerRef.current.set(fromId, apply(bucket));
        if (selectedIdRef.current === fromId) setMessages(apply);
      } catch (e) {
        console.error(e);
      }
    });

    socket.on('message:deleted', ({ messageId, fromId }) => {
      const apply = (prev) => prev.filter((m) => m.id !== messageId);
      const bucket = messagesByPeerRef.current.get(fromId);
      if (bucket) messagesByPeerRef.current.set(fromId, apply(bucket));
      if (selectedIdRef.current === fromId) setMessages(apply);
    });

    socket.on('typing', ({ fromId, isTyping }) => {
      if (fromId === selectedIdRef.current) setTypingUserId(isTyping ? fromId : null);
    });

    socket.on('disconnect', () => {
      setSocketReady(false);
    });

    socket.on('force-logout', () => {
      cleanupCall();
      onLogout();
    });

    socket.on('call:incoming', (incoming) => {
      setCallState({ mode: 'incoming', ...incoming });
      setCallNotice(`${incoming.fromName} is calling...`);
    });

    socket.on('call:accepted', async ({ byId }) => {
      if (!pendingCallPeerRef.current || byId !== pendingCallPeerRef.current) return;
      try {
        setCallState((prev) => (prev ? { ...prev, mode: 'active' } : prev));
        const pc = await ensurePeerConnection(byId);
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        socket.emit('call:signal', {
          toId: byId,
          data: { sdp: pc.localDescription }
        });
        setCallNotice('Call connected.');
      } catch (e) {
        setCallNotice(e.message);
      }
    });

    socket.on('call:rejected', () => {
      setCallNotice('Call rejected.');
      cleanupCall();
    });

    socket.on('call:signal', async ({ fromId, data }) => {
      try {
        let pc = pcRef.current;
        if (!pc) {
          pc = await ensurePeerConnection(fromId);
        }
        if (data.sdp) {
          await pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
          if (data.sdp.type === 'offer') {
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            socket.emit('call:signal', { toId: fromId, data: { sdp: pc.localDescription } });
            setCallState((prev) => prev ? { ...prev, mode: 'active' } : prev);
            setCallNotice('Call connected.');
          }
        } else if (data.candidate) {
          try {
            await pc.addIceCandidate(new RTCIceCandidate(data.candidate));
          } catch { }
        }
      } catch (e) {
        setCallNotice(e.message);
      }
    });

    socket.on('call:ended', () => {
      setCallNotice('Call ended.');
      cleanupCall();
    });

    return () => {
      mounted = false;
      socket.disconnect();
      socketRef.current = null;
      cleanupCall();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  useEffect(() => {
    if (!contacts.length && socketRef.current) refreshContacts();
    if (selectedId) {
      const contact = contacts.find((c) => c.id === selectedId);
      if (contact?.publicKey) {
        loadChat(selectedId);
      }
    }
  }, [contacts]);

  useEffect(() => {
    if (selectedId) loadChat(selectedId);
    setReplyTarget(null);
    setEditingMessage(null);
    setActiveMenuId(null);
    setShowEmoji(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  useEffect(() => {
    const markActivity = () => {
      if (callState?.mode === 'active' || callState?.mode === 'incoming' || callState?.mode === 'outgoing') return;
      clearTimeout(inactivityRef.current);
      inactivityRef.current = setTimeout(() => {
        logout();
      }, 300000);
    };

    const events = ['mousedown', 'keydown', 'touchstart', 'scroll', 'click', 'mousemove'];
    events.forEach((evt) => window.addEventListener(evt, markActivity));
    markActivity();

    return () => {
      clearTimeout(inactivityRef.current);
      events.forEach((evt) => window.removeEventListener(evt, markActivity));
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [callState]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, selectedId, typingUserId, callNotice]);

  // 👇 YAHAN PASTE KARO
  useEffect(() => {
    const resize = () => {
      const mobile = window.innerWidth <= 768;

      setIsMobile(mobile);

      if (!mobile) {
        setMobileChatOpen(false);
      }
    };

    window.addEventListener("resize", resize);

    resize();

    return () => window.removeEventListener("resize", resize);
  }, []);

  const sendText = async () => {
    if (!selectedContact || !composer.trim()) return;

    if (editingMessage) {
      const plain = { kind: 'text', text: composer.trim() };
      if (editingMessage.replyTo) plain.replyTo = editingMessage.replyTo;
      try {
        const payload = await encryptFor(selectedContact.id, plain);
        socketRef.current?.emit('message:edit', {
          messageId: editingMessage.id,
          toId: selectedContact.id,
          ...payload
        }, (ack) => {
          if (ack?.ok) {
            const apply = (prev) => prev.map((m) => (m.id === editingMessage.id ? { ...m, content: composer.trim(), edited: true } : m));
            setMessages(apply);
            const bucket = messagesByPeerRef.current.get(selectedContact.id);
            if (bucket) messagesByPeerRef.current.set(selectedContact.id, apply(bucket));
          }
        });
      } catch (e) {
        setError(e.message);
      }
      setEditingMessage(null);
      setComposer('');
      socketRef.current?.emit('typing', {
        toId: selectedContact.id,
        isTyping: false
      });

      clearTimeout(typingTimeoutRef.current);
      return;
    }

    const plain = { kind: 'text', text: composer.trim() };
    if (replyTarget) {
      plain.replyTo = {
        id: replyTarget.id,
        kind: replyTarget.payloadKind,
        preview: replyPreviewFor(replyTarget.payloadKind, replyTarget.content, replyTarget.fileName),
        fromMe: replyTarget.mine
      };
    }
    let payload;
    try {
      payload = await encryptFor(selectedContact.id, plain);
    } catch (e) {
      setError(e.message);
      return;
    }
    const tempText = composer.trim();
    const tempReply = plain.replyTo || null;
    setComposer('');
    socketRef.current?.emit('typing', {
      toId: selectedContact.id,
      isTyping: false
    });

    clearTimeout(typingTimeoutRef.current);
    setReplyTarget(null);
    socketRef.current?.emit('message:send', {
      toId: selectedContact.id,
      type: 'text',
      ...payload
    }, (ack) => {
      if (ack?.ok) {
        const newMsg = {
          id: ack.messageId,
          fromId: currentUser.id,
          toId: selectedContact.id,
          mine: true,
          type: 'text',
          payloadKind: 'text',
          content: tempText,
          replyTo: tempReply,
          createdAt: new Date().toISOString(),
          seenAt: null
        };
        setMessages((prev) => [...prev, newMsg]);
        const bucket = messagesByPeerRef.current.get(selectedContact.id) || [];
        messagesByPeerRef.current.set(selectedContact.id, [...bucket, newMsg]);
      }
      refreshContacts();
    });
  };

  const handleFileSelect = (file) => {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      setError('File is too large (max ~14MB).');
      return;
    }
    const previewUrl = file.type.startsWith('image/') ? URL.createObjectURL(file) : null;
    setSelectedFile({
      file,
      previewUrl,
      name: file.name,
      kind: file.type.startsWith('image/') ? 'photo' : 'document'
    });
  };

  const handleSend = async () => {
    if (!selectedContact) return;
    if (selectedFile) {
      const fileToSend = selectedFile.file;
      setSelectedFile(null);
      await sendFile(fileToSend);
    }
    if (composer.trim()) {
      await sendText();
    }
  };

  const MAX_FILE_BYTES = 14 * 1024 * 1024; // ~14MB raw (base64 adds ~33%, stays under the 20MB transport limit)
  const replyPreviewFor = (kind, content, fileName) => {
    if (kind === 'photo') return '📷 Photo';
    if (kind === 'document') return `📎 ${fileName || 'Document'}`;
    return String(content || '').slice(0, 120);
  };

  const sendFile = async (file) => {
    if (!selectedContact || !file) return;
    if (file.size > MAX_FILE_BYTES) {
      setError('File is too large (max ~14MB).');
      return;
    }
    const kind = file.type.startsWith('image/') ? 'photo' : 'document';
    const dataUrl = await fileToDataUrl(file);
    const plain = { kind, dataUrl, name: file.name, mimeType: file.type, size: file.size };
    if (replyTarget) {
      plain.replyTo = {
        id: replyTarget.id,
        kind: replyTarget.payloadKind,
        preview: replyPreviewFor(replyTarget.payloadKind, replyTarget.content, replyTarget.fileName),
        fromMe: replyTarget.mine
      };
    }
    let payload;
    try {
      payload = await encryptFor(selectedContact.id, plain);
    } catch (e) {
      setError(e.message);
      return;
    }
    const tempReply = plain.replyTo || null;
    setReplyTarget(null);
    socketRef.current?.emit('message:send', {
      toId: selectedContact.id,
      type: kind,
      fileName: file.name,
      mimeType: file.type,
      ...payload
    }, (ack) => {
      if (ack?.ok) {
        const newMsg = {
          id: ack.messageId,
          fromId: currentUser.id,
          toId: selectedContact.id,
          mine: true,
          type: kind,
          payloadKind: kind,
          content: dataUrl,
          fileName: file.name,
          mimeType: file.type,
          fileSize: file.size,
          replyTo: tempReply,
          createdAt: new Date().toISOString(),
          seenAt: null
        };
        setMessages((prev) => [...prev, newMsg]);
        const bucket = messagesByPeerRef.current.get(selectedContact.id) || [];
        messagesByPeerRef.current.set(selectedContact.id, [...bucket, newMsg]);
      }
      refreshContacts();
    });
  };

  const copyMessage = async (msg) => {
    if (msg.payloadKind !== 'text') return;
    try {
      await navigator.clipboard.writeText(msg.content || '');
    } catch { }
    setActiveMenuId(null);
  };

  const startReply = (msg) => {
    setReplyTarget(msg);
    setEditingMessage(null);
    setActiveMenuId(null);
  };

  const startEdit = (msg) => {
    if (!msg.mine || msg.payloadKind !== 'text') return;
    setEditingMessage(msg);
    setReplyTarget(null);
    setComposer(msg.content || '');
    setActiveMenuId(null);
  };

  const deleteMessage = (msg, scope) => {
    setActiveMenuId(null);
    const apply = (prev) => prev.filter((m) => m.id !== msg.id);
    setMessages(apply);
    const peerId = msg.mine ? msg.toId : msg.fromId;
    const bucket = messagesByPeerRef.current.get(peerId);
    if (bucket) messagesByPeerRef.current.set(peerId, apply(bucket));
    socketRef.current?.emit('message:delete', {
      messageId: msg.id,
      toId: selectedContact?.id,
      scope
    });
  };

  const insertEmoji = (emoji) => {
    setComposer((prev) => prev + emoji);
  };

  const selectedStatus = selectedContact
    ? selectedContact.online
      ? 'Online'
      : selectedContact.showLastSeen
        ? `Last seen ${formatLastSeen(selectedContact.lastSeen)}`
        : 'Offline'
    : '';

  return (
    <div className="messenger-shell">
      <aside
        className={`contacts-panel ${isMobile && mobileChatOpen ? "mobile-hide" : ""
          }`}
      >
        <div className="contacts-head">
          <div>
            <div className="small-label">Logged in as</div>
            <div className="title-strong">{currentUser.displayName}</div>
          </div>
          <button className="ghost-btn" onClick={logout}>Logout</button>
        </div>

        <div className={`connection-chip ${socketReady ? 'ready' : ''}`}>
          {socketReady ? 'Connected' : 'Connecting...'}
        </div>

        <div className="contacts-list">
          {contacts.map((contact) => (
            <button
              key={contact.id}
              className={`contact-row ${selectedId === contact.id ? 'active' : ''}`}
              onClick={() => {
                setSelectedId(contact.id);

                if (isMobile) {
                  setMobileChatOpen(true);
                }
              }}
            >
              <div className={`avatar initials ${contact.online ? 'online' : ''}`}>{contact.initials || initials(contact.displayName)}</div>
              <div className="contact-meta">
                <div className="contact-top">
                  <strong>{contact.displayName}</strong>
                  {contact.unreadCount ? <span className="badge">{contact.unreadCount}</span> : null}
                </div>
                <div className="contact-sub">
                  <span className={contact.online ? 'online-pill' : 'offline-pill'}>
                    {contact.online ? 'Online' : 'Offline'}
                  </span>
                  <span className="muted">{contact.showLastSeen ? `Last seen: ${formatLastSeen(contact.lastSeen)}` : 'Last seen hidden'}</span>
                </div>
              </div>
            </button>
          ))}
        </div>
      </aside >

      <main
        className={`chat-panel ${isMobile && !mobileChatOpen ? "mobile-hide" : ""
          }`}
      >
        {selectedContact ? (
          <>
            <header className="chat-head">
              <div className="chat-head-main">
                {isMobile && mobileChatOpen && (
                  <button
                    className="back-btn"
                    onClick={() => {
                      setMobileChatOpen(false);
                      setSelectedId(null);
                    }}
                  >
                    ←
                  </button>
                )}
                <div className="avatar initials large">{selectedContact.initials || initials(selectedContact.displayName)}</div>
                <div>
                  <div className="title-strong">{selectedContact.displayName}</div>
                  <div className="muted">{typingUserId === selectedContact.id ? 'typing...' : selectedStatus}</div>
                </div>
              </div>

              <div className="chat-head-actions">
                <button className="ghost-btn" onClick={() => startOutgoingCall(selectedContact)} disabled={Boolean(callState)}>
                  📞 Call
                </button>
                <button className="danger-btn" onClick={logout}>⚡ Panic</button>
              </div>
            </header>

            {error ? <div className="error-box inline-error" onClick={() => setError('')}>{error}</div> : null}

            <section className="message-list" ref={scrollRef}>
              {loadingChat ? <div className="empty-state">Loading chat...</div> : null}
              {!loadingChat && messages.length === 0 ? (
                <div className="empty-state">Start a private chat.</div>
              ) : null}
              {messages.map((m) => (
                <MessageRow
                  key={m.id}
                  m={m}
                  mine={m.mine}
                  selectedContact={selectedContact}
                  activeMenuId={activeMenuId}
                  setActiveMenuId={setActiveMenuId}
                  startReply={startReply}
                  copyMessage={copyMessage}
                  startEdit={startEdit}
                  deleteMessage={deleteMessage}
                  formatFileSize={formatFileSize}
                  onOpenImage={(imgData) => setViewingImage(imgData)}
                  scrollRef={scrollRef}
                />
              ))}
              {callNotice ? <div className="call-note">{callNotice}</div> : null}
            </section>

            {selectedFile ? (
              <div className="composer-context">
                <div className="composer-context-text">
                  <span className="small-label">Selected attachment</span>
                  {selectedFile.kind === 'photo' ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <img src={selectedFile.previewUrl} alt="Preview" className="composer-image-preview" />
                      <span>{selectedFile.name}</span>
                    </div>
                  ) : (
                    <span>📎 {selectedFile.name}</span>
                  )}
                </div>
                <button className="ghost-btn" onClick={() => setSelectedFile(null)}>✕</button>
              </div>
            ) : null}

            {replyTarget ? (
              <div className="composer-context">
                <div className="composer-context-text">
                  <span className="small-label">Replying to</span>
                  <span>{replyPreviewFor(replyTarget.payloadKind, replyTarget.content, replyTarget.fileName)}</span>
                </div>
                <button className="ghost-btn" onClick={() => setReplyTarget(null)}>✕</button>
              </div>
            ) : null}

            {editingMessage ? (
              <div className="composer-context">
                <div className="composer-context-text">
                  <span className="small-label">Editing message</span>
                </div>
                <button className="ghost-btn" onClick={() => { setEditingMessage(null); setComposer(''); }}>✕</button>
              </div>
            ) : null}

            {showEmoji ? (
              <div className="emoji-picker">
                {EMOJIS.map((e) => (
                  <button key={e} className="emoji-btn" onClick={() => insertEmoji(e)}>{e}</button>
                ))}
              </div>
            ) : null}

            <footer className="composer">
              <label className="photo-btn" title="Take photo with camera">
                📷
                <input
                  type="file"
                  accept="image/*"
                  capture="environment"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) handleFileSelect(file);
                    e.target.value = '';
                  }}
                />
              </label>

              <label className="photo-btn" title="Attach file or image">
                📎
                <input
                  type="file"
                  accept="image/*,video/*,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) handleFileSelect(file);
                    e.target.value = '';
                  }}
                />
              </label>

              <button className="ghost-btn emoji-toggle" onClick={() => setShowEmoji((v) => !v)} type="button">😊</button>

              <input
                value={composer}
                onChange={(e) => {
                  const value = e.target.value;

                  setComposer(value);

                  if (!selectedContact) return;

                  socketRef.current?.emit('typing', {
                    toId: selectedContact.id,
                    isTyping: value.trim().length > 0
                  });

                  clearTimeout(typingTimeoutRef.current);

                  typingTimeoutRef.current = setTimeout(() => {
                    socketRef.current?.emit('typing', {
                      toId: selectedContact.id,
                      isTyping: false
                    });
                  }, 1500);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleSend();
                }}
                placeholder={editingMessage ? 'Edit message...' : 'Type message...'}
              />

              <button
                className="primary-btn send-btn"
                onClick={handleSend}
                disabled={!composer.trim() && !selectedFile}
              >
                {editingMessage ? '✓' : '➤'}
              </button>
            </footer>
          </>
        ) : (
          <div className="empty-chat">
            <div className="empty-state">Select a contact to begin.</div>
          </div>
        )}
      </main>

      {
        callState ? (
          <CallOverlay
            callState={callState}
            onAccept={acceptIncomingCall}
            onReject={rejectIncomingCall}
            onEnd={endCall}
            remoteAudioRef={remoteAudioRef}
          />
        ) : null
      }

      {viewingImage ? (
        <div className="image-viewer-overlay" onClick={() => setViewingImage(null)}>
          <button
            className="image-viewer-close"
            onClick={(e) => {
              e.stopPropagation();
              setViewingImage(null);
            }}
            aria-label="Close image viewer"
          >
            ✕
          </button>
          <div className="image-viewer-content" onClick={(e) => e.stopPropagation()}>
            <img
              src={viewingImage.src}
              alt={viewingImage.fileName || 'Full view'}
              className="image-viewer-img"
            />
          </div>
        </div>
      ) : null}
    </div >
  );
}

function CallOverlay({ callState, onAccept, onReject, onEnd, remoteAudioRef }) {
  return (
    <div className="call-overlay">
      <div className="call-card">
        <div className="small-label">Audio Call</div>
        <h3>{callState.mode === 'incoming' ? `Incoming from ${callState.fromName}` : callState.peerName}</h3>
        <div className="muted">
          {callState.mode === 'incoming'
            ? 'Accept or reject the call.'
            : callState.mode === 'outgoing'
              ? 'Ringing...'
              : 'Connected'}
        </div>

        <audio ref={remoteAudioRef} autoPlay />

        <div className="call-actions">
          {callState.mode === 'incoming' ? (
            <>
              <button className="primary-btn" onClick={() => onAccept(callState)}>Accept</button>
              <button className="danger-btn" onClick={() => onReject(callState)}>Reject</button>
            </>
          ) : (
            <button className="danger-btn" onClick={onEnd}>End Call</button>
          )}
        </div>
      </div>
    </div>
  );
}
function MessageRow({ m, mine, selectedContact, activeMenuId, setActiveMenuId, startReply, copyMessage, startEdit, deleteMessage, formatFileSize, onOpenImage, scrollRef }) {
  const [dragX, setDragX] = useState(0);
  const startXRef = useRef(0);
  const startYRef = useRef(0);
  const isHorizontalRef = useRef(false);
  const draggingRef = useRef(false);
  const SWIPE_THRESHOLD = 55;
  const MAX_DRAG = 80;

  const onTouchStart = (e) => {
    startXRef.current = e.touches[0].clientX;
    startYRef.current = e.touches[0].clientY;
    draggingRef.current = true;
    isHorizontalRef.current = false;
  };

  const onTouchMove = (e) => {
    if (!draggingRef.current) return;
    const deltaX = e.touches[0].clientX - startXRef.current;
    const deltaY = e.touches[0].clientY - startYRef.current;

    if (!isHorizontalRef.current) {
      if (Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > 6) {
        isHorizontalRef.current = true;
      } else if (Math.abs(deltaY) > 6) {
        draggingRef.current = false;
        setDragX(0);
        return;
      }
    }

    if (isHorizontalRef.current) {
      const clamped = mine
        ? Math.max(-MAX_DRAG, Math.min(0, deltaX))
        : Math.max(0, Math.min(MAX_DRAG, deltaX));
      setDragX(clamped);
    }
  };

  const onTouchEnd = () => {
    draggingRef.current = false;
    isHorizontalRef.current = false;
    if (Math.abs(dragX) >= SWIPE_THRESHOLD) {
      startReply(m);
    }
    setDragX(0);
  };

  const showReplyIcon = Math.abs(dragX) > 12;

  const replyWho = m.replyTo
    ? (mine
      ? (m.replyTo.fromMe ? 'You' : selectedContact?.displayName || 'Contact')
      : (m.replyTo.fromMe ? selectedContact?.displayName || 'Contact' : 'You'))
    : '';

  return (
    <div
      className={`bubble-row ${mine ? 'mine' : 'theirs'}`}
      onTouchStart={onTouchStart}
      onTouchMove={onTouchMove}
      onTouchEnd={onTouchEnd}
      style={{ position: 'relative' }}
    >
      {showReplyIcon ? (
        <span
          className="swipe-reply-icon"
          style={{
            opacity: Math.min(1, Math.abs(dragX) / SWIPE_THRESHOLD),
            [mine ? 'right' : 'left']: `${Math.abs(dragX) + 6}px`
          }}
        >
          ↩
        </span>
      ) : null}

      <div
        className={`bubble ${mine ? 'bubble-mine' : 'bubble-theirs'}`}
        onClick={() => setActiveMenuId(activeMenuId === m.id ? null : m.id)}
        style={{
          transform: `translateX(${dragX}px)`,
          transition: draggingRef.current ? 'none' : 'transform .18s ease'
        }}
      >
        {m.replyTo ? (
          <div className="reply-preview">
            <span className="reply-who">{replyWho}</span>
            <span className="reply-text">{m.replyTo.preview}</span>
          </div>
        ) : null}

        {m.payloadKind === 'photo' ? (
          <img
            src={m.content}
            alt={m.fileName || 'photo'}
            className="bubble-image"
            onLoad={() => {
              if (scrollRef?.current) {
                scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
              }
            }}
            onClick={(e) => {
              e.stopPropagation();
              onOpenImage?.({ src: m.content, fileName: m.fileName });
            }}
          />
        ) : m.payloadKind === 'document' ? (
          <a
            href={m.content}
            download={m.fileName || 'file'}
            className="file-card"
            onClick={(e) => e.stopPropagation()}
          >
            <span className="file-icon">📄</span>
            <span className="file-info">
              <span className="file-name">{m.fileName || 'Document'}</span>
              <span className="file-size">{formatFileSize(m.fileSize)} · Tap to download</span>
            </span>
          </a>
        ) : (
          <div>{m.content}</div>
        )}

        <div className="bubble-meta">
          {m.edited ? <span className="edited-tag">edited</span> : null}
          <span>{new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          {m.mine ? <span>{m.seenAt ? 'Seen' : 'Sent'}</span> : null}
        </div>

        {activeMenuId === m.id ? (
          <div className="msg-actions" onClick={(e) => e.stopPropagation()}>
            <button onClick={() => startReply(m)}>↩ Reply</button>
            {m.payloadKind === 'text' ? <button onClick={() => copyMessage(m)}>⧉ Copy</button> : null}
            {m.mine && m.payloadKind === 'text' ? <button onClick={() => startEdit(m)}>✎ Edit</button> : null}
            {m.mine ? <button onClick={() => deleteMessage(m, 'everyone')}>🗑 Delete for everyone</button> : null}
            <button onClick={() => deleteMessage(m, 'me')}>🗑 Delete for me</button>
          </div>
        ) : null}
      </div>
    </div>
  );
}
