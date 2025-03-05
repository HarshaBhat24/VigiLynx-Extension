require('dotenv').config();
const express = require('express');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const FormData = require('form-data');
const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB limit
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:5173');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

async function fetchGeminiData(type, input, vtStats, vtFullData) {
  console.log(`Fetching Gemini data for ${type}: ${input}`);
  const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${process.env.GEMINI_API_KEY}`;
  const prompt = `
    Analyze ${type}: ${input} for cybersecurity purposes with detailed insights.
    VirusTotal stats: ${JSON.stringify(vtStats)}.
    Threat names: ${vtFullData.threat_names?.join(', ') || 'None'}.
    Categories: ${Object.values(vtFullData.categories || {}).join(', ') || 'Unknown'}.
    Reputation: ${vtFullData.reputation || 'N/A'}.
    Provide a comprehensive, structured cybersecurity report with:
    - **Threats & Vulnerabilities:** List specific threats (e.g., malware, phishing, ransomware) based on VirusTotal data, or "No specific threats detected" with general risks (e.g., phishing, unverified content).
    - **Reputation:** Assess domain trustworthiness, known incidents, or historical data if available; otherwise, provide general analysis (e.g., domain age, common usage).
    - **Context:** Describe the input's purpose (e.g., website, file type) and associated risks, including known associations or potential misuse; suggest contexts if unclear.
    - **Safety Tips:** Provide 4+ actionable, tailored tips (e.g., verify HTTPS, use 2FA, scan with antivirus, check reviews).
    - **JSON Pie Chart:** {"Safe": X, "Malicious": Y, "Suspicious": Z}, ensuring X + Y + Z = 100 for a clear summary.
    Ensure detailed, informative content even for safe inputs, avoiding empty or vague responses.Don't give points.
  `;

  try {
    const response = await axios.post(geminiUrl, { contents: [{ parts: [{ text: prompt }] }] });
    const text = response.data.candidates[0].content.parts[0].text;
    console.log(`Gemini Response for ${type}:`, text);
    return text;
  } catch (error) {
    console.error(`Gemini Error for ${type}:`, error.message);
    const isSafe = vtStats.malicious === 0 && vtStats.suspicious === 0;
    const total = vtStats.harmless + vtStats.undetected + vtStats.malicious + vtStats.suspicious;
    const safePercentage = total > 0 ? Math.round(((vtStats.harmless + vtStats.undetected) / total) * 100) : (isSafe ? 100 : 0);
    const maliciousPercentage = total > 0 ? Math.round((vtStats.malicious / total) * 100) : 0;
    const suspiciousPercentage = total > 0 ? Math.round((vtStats.suspicious / total) * 100) : 0;

    const fallback = `
      Cybersecurity Report for ${input}
      - Threats & Vulnerabilities: ${vtStats.malicious > 0 || vtStats.suspicious > 0 ? `Detected: ${vtFullData.threat_names?.join(', ') || 'Unknown threats'}. Potential risks include phishing, malware, or unauthorized access.` : 'No specific threats detected. General risks: phishing attempts, unverified content, or outdated security.'}
      - Reputation: ${vtFullData.reputation ? `Score: ${vtFullData.reputation}. ${vtFullData.reputation > 0 ? 'Generally trusted.' : 'Potentially risky.'}` : 'No reputation data available. Likely a lesser-known entity; verify its legitimacy.'}
      - Context: ${vtFullData.categories ? `Known categories: ${Object.values(vtFullData.categories).join(', ')}.` : 'Purpose unclear.'} ${type === 'URL' ? 'Could be a website, service, or redirect.' : type === 'File' ? 'File type may indicate its use (e.g., executable, image).' : 'Likely a ${type.toLowerCase()} with unknown intent.'} Exercise caution.
      - Safety Tips:
        - Ensure connections use HTTPS for secure data transmission.
        - Avoid clicking unverified links or downloading unknown files.
        - Use up-to-date antivirus software to detect threats.
        - Verify the source through trusted reviews or official channels.
        - Enable two-factor authentication where applicable.
      - JSON Pie Chart: {"Safe": ${safePercentage}, "Malicious": ${maliciousPercentage}, "Suspicious": ${suspiciousPercentage}}
    `;
    console.log(`Gemini Fallback for ${type}:`, fallback);
    return fallback;
  }
}

app.get('/api/scan', async (req, res) => {
  const { input } = req.query;
  if (!input) {
    console.log('No input provided');
    return res.status(400).json({ error: 'Input is required' });
  }
  console.log('Received scan request for:', input);

  let vtStats = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
  let vtFullData = { reputation: 0, threat_names: [], categories: {} };
  let type;

  try {
    const vtHeaders = { 'x-apikey': process.env.VIRUSTOTAL_API_KEY, 'Accept': 'application/json' };

    if (input.includes('://') || input.startsWith('www.')) {
      type = 'URL';
      const encodedUrl = encodeURIComponent(input);
      const urlId = Buffer.from(encodedUrl).toString('base64').replace(/=/g, '');
      console.log('Processing URL:', input, 'Encoded URL:', encodedUrl, 'URL ID:', urlId);

      try {
        const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, { headers: vtHeaders });
        vtStats = vtResponse.data.data.attributes.last_analysis_stats;
        vtFullData = vtResponse.data.data.attributes;
        console.log('VirusTotal URL GET Response:', vtStats);
      } catch (getError) {
        console.log('URL GET failed, trying POST:', getError.message);
        const vtPostResponse = await axios.post('https://www.virustotal.com/api/v3/urls', `url=${encodedUrl}`, {
          headers: { ...vtHeaders, 'Content-Type': 'application/x-www-form-urlencoded' },
        });
        const analysisId = vtPostResponse.data.data.id;
        console.log('URL POST submitted, Analysis ID:', analysisId);

        for (let i = 0; i < 5; i++) {
          await new Promise(r => setTimeout(r, 2000));
          const analysis = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers: vtHeaders });
          console.log(`Analysis attempt ${i + 1}:`, analysis.data.data.attributes.status);
          if (analysis.data.data.attributes.status === 'completed') {
            vtStats = analysis.data.data.attributes.stats;
            vtFullData = analysis.data.data.attributes;
            console.log('VirusTotal URL Analysis Complete:', vtStats);
            break;
          }
          if (i === 4) throw new Error('URL analysis timed out');
        }
      }
    } else if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(input)) {
      type = 'Hash';
      console.log('Processing Hash:', input);
      const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${input}`, { headers: vtHeaders });
      vtStats = vtResponse.data.data.attributes.last_analysis_stats;
      vtFullData = vtResponse.data.data.attributes;
      console.log('VirusTotal Hash Response:', vtStats);
    } else if (/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(input)) {
      type = 'Domain';
      console.log('Processing Domain:', input);
      const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/domains/${input}`, { headers: vtHeaders });
      vtStats = vtResponse.data.data.attributes.last_analysis_stats;
      vtFullData = vtResponse.data.data.attributes;
      console.log('VirusTotal Domain Response:', vtStats);
    } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(input)) {
      type = 'IP Address';
      console.log('Processing IP:', input);
      const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${input}`, { headers: vtHeaders });
      vtStats = vtResponse.data.data.attributes.last_analysis_stats;
      vtFullData = vtResponse.data.data.attributes;
      console.log('VirusTotal IP Response:', vtStats);
    } else {
      console.log('Invalid input type');
      return res.status(400).json({ error: 'Invalid input type (URL, domain, hash, or IP required)' });
    }

    const isSafe = vtStats.malicious === 0 && vtStats.suspicious === 0;
    const safetyScore = vtFullData.reputation !== undefined
      ? Math.round((vtFullData.reputation + 100) / 2)
      : Math.round(((vtStats.harmless + vtStats.undetected) / (vtStats.harmless + vtStats.undetected + vtStats.malicious + vtStats.suspicious)) * 100) || 0;

    const geminiData = await fetchGeminiData(type, input, vtStats, vtFullData);

    let recordId = null;
    try {
      const { data, error } = await supabase.from('scan_insights').insert([{ input, type, is_safe: isSafe, safety_score: safetyScore, vt_stats: vtStats, vt_full_data: vtFullData, gemini_insights: geminiData }]).select();
      if (error) throw error;
      recordId = data[0].id;
      console.log('Scan completed, record ID:', recordId);
    } catch (supabaseError) {
      console.error('Supabase Insert Error:', supabaseError.message);
      console.log('Proceeding with response despite Supabase failure');
    }

    res.json({ isSafe, safetyScore, vtStats, vtFullData, geminiInsights: geminiData, recordId });
  } catch (error) {
    console.error('Scan Error:', error.message);
    res.status(500).json({ error: `Scan failed: ${error.message}`, isSafe: true, safetyScore: 0, vtStats, vtFullData, geminiInsights: '' });
  }
});

app.post('/api/scan-file', upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file || file.size === 0) {
    console.log('No file provided or file is empty');
    return res.status(400).json({ error: 'Valid file is required' });
  }
  console.log('Received file scan request, file name:', file.originalname, 'file size:', file.size, 'bytes');
  console.log('File data sample (first 50 bytes):', file.buffer.slice(0, 50).toString('hex'));

  let vtStats = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
  let vtFullData = { reputation: 0, threat_names: [], categories: {} };

  try {
    const formData = new FormData();
    formData.append('file', file.buffer, file.originalname);
    const vtHeaders = {
      'x-apikey': process.env.VIRUSTOTAL_API_KEY,
      ...formData.getHeaders(),
    };
    console.log('Sending file to VirusTotal with headers:', vtHeaders);
    const vtResponse = await axios.post('https://www.virustotal.com/api/v3/files', formData, { headers: vtHeaders });
    const analysisId = vtResponse.data.data.id;
    console.log('File POST submitted, Analysis ID:', analysisId);

    for (let i = 0; i < 5; i++) {
      await new Promise(r => setTimeout(r, 2000));
      const analysis = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } });
      console.log(`File analysis attempt ${i + 1}:`, analysis.data.data.attributes.status);
      if (analysis.data.data.attributes.status === 'completed') {
        vtStats = analysis.data.data.attributes.stats;
        vtFullData = analysis.data.data.attributes;
        console.log('VirusTotal File Analysis Complete:', vtStats);
        break;
      }
      if (i === 4) throw new Error('File analysis timed out');
    }

    const isSafe = vtStats.malicious === 0 && vtStats.suspicious === 0;
    const safetyScore = vtFullData.reputation !== undefined
      ? Math.round((vtFullData.reputation + 100) / 2)
      : Math.round(((vtStats.harmless + vtStats.undetected) / (vtStats.harmless + vtStats.undetected + vtStats.malicious + vtStats.suspicious)) * 100) || 0;

    const geminiData = await fetchGeminiData('File', file.originalname, vtStats, vtFullData);

    let recordId = null;
    try {
      const { data, error } = await supabase.from('file_insights').insert([{ filename: file.originalname, is_safe: isSafe, safety_score: safetyScore, vt_stats: vtStats, vt_full_data: vtFullData, gemini_insights: geminiData }]).select();
      if (error) throw error;
      recordId = data[0].id;
      console.log('File scan completed, record ID:', recordId);
    } catch (supabaseError) {
      console.error('Supabase Insert Error:', supabaseError.message);
      console.log('Proceeding with response despite Supabase failure');
    }

    res.json({ isSafe, safetyScore, vtStats, vtFullData, geminiInsights: geminiData, recordId });
  } catch (error) {
    console.error('File Scan Error:', error.message, 'Response:', error.response?.data);
    res.status(500).json({ error: `File scan failed: ${error.message}`, details: error.response?.data });
  }
});

app.get('/api/insights', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('scan_insights')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Insights Fetch Error:', error.message);
    res.status(500).json({ error: `Failed to fetch insights: ${error.message}` });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


// require('dotenv').config();
// const express = require('express');
// const axios = require('axios');
// const { createClient } = require('@supabase/supabase-js');
// const multer = require('multer');
// const FormData = require('form-data');
// const app = express();
// const PORT = process.env.PORT || 5000;

// app.use(express.json());
// const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB limit
// app.use((req, res, next) => {
//   res.header('Access-Control-Allow-Origin', 'http://localhost:5173');
//   res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
//   next();
// });

// const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// async function fetchGeminiData(type, input, vtStats, vtFullData) {
//   console.log(`Fetching Gemini data for ${type}: ${input}`);
//   const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${process.env.GEMINI_API_KEY}`;

//   const prompt = `
//     Analyze ${type}: ${input} for cybersecurity purposes. VirusTotal stats: ${JSON.stringify(vtStats)}. Threat names: ${vtFullData.threat_names?.join(', ') || 'None'}. Categories: ${Object.values(vtFullData.categories || {}).join(', ') || 'Unknown'}. Reputation: ${vtFullData.reputation || 'N/A'}.
//     Return a structured report as a single-line string with sections separated by " | " (no extra spaces or newlines). Use this exact format:
//     Threats & Vulnerabilities: <content> | Reputation: <content> | Context: <content> | Safety Tips: - <tip1> - <tip2> - <tip3> - <tip4> | JSON Pie Chart: {"Safe": X, "Malicious": Y, "Suspicious": Z}
//     - No dots or extra punctuation after section titles.
//     - Pie chart must use exact labels "Safe", "Malicious", "Suspicious", summing to 100.
//     - No newlines or extra spaces within or between sections.
//   `;

//   try {
//     const response = await axios.post(geminiUrl, { contents: [{ parts: [{ text: prompt }] }] });
//     let text = response.data.candidates[0].content.parts[0].text;

//     // Clean any unexpected newlines or dots
//     text = text
//       .replace(/\n/g, '') // Remove all newlines
//       .replace(/\|\s*\.\s*/g, '|') // Remove dots after section separators
//       .replace(/\s*\|\s*/g, '|') // Normalize spacing around separators
//       .trim();

//     console.log(`Gemini Response for ${type}:`, text);
//     return text;
//   } catch (error) {
//     console.error(`Gemini Error for ${type}:`, error.message);
//     const isSafe = vtStats.malicious === 0 && vtStats.suspicious === 0;
//     const total = vtStats.harmless + vtStats.undetected + vtStats.malicious + vtStats.suspicious || 1;
//     const safePercentage = total > 0 ? Math.round(((vtStats.harmless + vtStats.undetected) / total) * 100) : (isSafe ? 100 : 0);
//     const maliciousPercentage = total > 0 ? Math.round((vtStats.malicious / total) * 100) : 0;
//     const suspiciousPercentage = total > 0 ? Math.round((vtStats.suspicious / total) * 100) : 0;

//     const fallback = `Threats & Vulnerabilities: ${vtStats.malicious > 0 || vtStats.suspicious > 0 ? `Detected: ${vtFullData.threat_names?.join(', ') || 'Unknown threats'}. Potential risks include phishing, malware, or unauthorized access.` : 'No specific threats detected. General risks: phishing attempts, unverified content, or outdated security.'} | Reputation: ${vtFullData.reputation ? `Score: ${vtFullData.reputation}. ${vtFullData.reputation > 0 ? 'Generally trusted.' : 'Potentially risky.'}` : 'No reputation data available. Likely a lesser-known entity; verify its legitimacy.'} | Context: ${vtFullData.categories ? `Known categories: ${Object.values(vtFullData.categories).join(', ')}.` : 'Purpose unclear.'} ${type === 'URL' ? 'Could be a website, service, or redirect.' : type === 'File' ? 'File type may indicate its use (e.g., executable, image).' : 'Likely a ${type.toLowerCase()} with unknown intent.'} Exercise caution. | Safety Tips: - Ensure connections use HTTPS for secure data transmission. - Avoid clicking unverified links or downloading unknown files. - Use up-to-date antivirus software to detect threats. - Verify the source through trusted reviews or official channels. - Enable two-factor authentication where applicable. | JSON Pie Chart: {"Safe": ${safePercentage}, "Malicious": ${maliciousPercentage}, "Suspicious": ${suspiciousPercentage}}`;

//     console.log(`Gemini Fallback for ${type}:`, fallback);
//     return fallback;
//   }
// }
// app.get('/api/scan', async (req, res) => {
//   const { input } = req.query;
//   if (!input) {
//     console.log('No input provided');
//     return res.status(400).json({ error: 'Input is required' });
//   }
//   console.log('Received scan request for:', input);

//   let vtStats = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
//   let vtFullData = { reputation: 0, threat_names: [], categories: {} };
//   let type;

//   try {
//     const vtHeaders = { 'x-apikey': process.env.VIRUSTOTAL_API_KEY, 'Accept': 'application/json' };

//     if (input.includes('://') || input.startsWith('www.')) {
//       type = 'URL';
//       const encodedUrl = encodeURIComponent(input);
//       const urlId = Buffer.from(encodedUrl).toString('base64').replace(/=/g, '');
//       console.log('Processing URL:', input, 'Encoded URL:', encodedUrl, 'URL ID:', urlId);

//       try {
//         const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, { headers: vtHeaders });
//         vtStats = vtResponse.data.data.attributes.last_analysis_stats;
//         vtFullData = vtResponse.data.data.attributes;
//         console.log('VirusTotal URL GET Response:', vtStats);
//       } catch (getError) {
//         console.log('URL GET failed, trying POST:', getError.message);
//         const vtPostResponse = await axios.post('https://www.virustotal.com/api/v3/urls', `url=${encodedUrl}`, {
//           headers: { ...vtHeaders, 'Content-Type': 'application/x-www-form-urlencoded' },
//         });
//         const analysisId = vtPostResponse.data.data.id;
//         console.log('URL POST submitted, Analysis ID:', analysisId);

//         for (let i = 0; i < 5; i++) {
//           await new Promise(r => setTimeout(r, 2000));
//           const analysis = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers: vtHeaders });
//           console.log(`Analysis attempt ${i + 1}:`, analysis.data.data.attributes.status);
//           if (analysis.data.data.attributes.status === 'completed') {
//             vtStats = analysis.data.data.attributes.stats;
//             vtFullData = analysis.data.data.attributes;
//             console.log('VirusTotal URL Analysis Complete:', vtStats);
//             break;
//           }
//           if (i === 4) throw new Error('URL analysis timed out');
//         }
//       }
//     } else if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(input)) {
//       type = 'Hash';
//       console.log('Processing Hash:', input);
//       const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${input}`, { headers: vtHeaders });
//       vtStats = vtResponse.data.data.attributes.last_analysis_stats;
//       vtFullData = vtResponse.data.data.attributes;
//       console.log('VirusTotal Hash Response:', vtStats);
//     } else if (/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(input)) {
//       type = 'Domain';
//       console.log('Processing Domain:', input);
//       const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/domains/${input}`, { headers: vtHeaders });
//       vtStats = vtResponse.data.data.attributes.last_analysis_stats;
//       vtFullData = vtResponse.data.data.attributes;
//       console.log('VirusTotal Domain Response:', vtStats);
//     } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(input)) {
//       type = 'IP Address';
//       console.log('Processing IP:', input);
//       const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${input}`, { headers: vtHeaders });
//       vtStats = vtResponse.data.data.attributes.last_analysis_stats;
//       vtFullData = vtResponse.data.data.attributes;
//       console.log('VirusTotal IP Response:', vtStats);
//     } else {
//       console.log('Invalid input type');
//       return res.status(400).json({ error: 'Invalid input type (URL, domain, hash, or IP required)' });
//     }

//     const isSafe = vtStats.malicious === 0 && vtStats.suspicious === 0;
//     const safetyScore = vtFullData.reputation !== undefined
//       ? Math.round((vtFullData.reputation + 100) / 2)
//       : Math.round(((vtStats.harmless + vtStats.undetected) / (vtStats.harmless + vtStats.undetected + vtStats.malicious + vtStats.suspicious)) * 100) || 0;

//     const geminiData = await fetchGeminiData(type, input, vtStats, vtFullData);

//     let recordId = null;
//     try {
//       const { data, error } = await supabase.from('scan_insights').insert([{ input, type, is_safe: isSafe, safety_score: safetyScore, vt_stats: vtStats, vt_full_data: vtFullData, gemini_insights: geminiData }]).select();
//       if (error) throw error;
//       recordId = data[0].id;
//       console.log('Scan completed, record ID:', recordId);
//     } catch (supabaseError) {
//       console.error('Supabase Insert Error:', supabaseError.message);
//       console.log('Proceeding with response despite Supabase failure');
//     }

//     res.json({ isSafe, safetyScore, vtStats, vtFullData, geminiInsights: geminiData, recordId });
//   } catch (error) {
//     console.error('Scan Error:', error.message);
//     res.status(500).json({ error: `Scan failed: ${error.message}`, isSafe: true, safetyScore: 0, vtStats, vtFullData, geminiInsights: '' });
//   }
// });

// app.post('/api/scan-file', upload.single('file'), async (req, res) => {
//   const file = req.file;
//   if (!file || file.size === 0) {
//     console.log('No file provided or file is empty');
//     return res.status(400).json({ error: 'Valid file is required' });
//   }
//   console.log('Received file scan request, file name:', file.originalname, 'file size:', file.size, 'bytes');
//   console.log('File data sample (first 50 bytes):', file.buffer.slice(0, 50).toString('hex'));

//   let vtStats = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
//   let vtFullData = { reputation: 0, threat_names: [], categories: {} };

//   try {
//     const formData = new FormData();
//     formData.append('file', file.buffer, file.originalname);
//     const vtHeaders = {
//       'x-apikey': process.env.VIRUSTOTAL_API_KEY,
//       ...formData.getHeaders(),
//     };
//     console.log('Sending file to VirusTotal with headers:', vtHeaders);
//     const vtResponse = await axios.post('https://www.virustotal.com/api/v3/files', formData, { headers: vtHeaders });
//     const analysisId = vtResponse.data.data.id;
//     console.log('File POST submitted, Analysis ID:', analysisId);

//     for (let i = 0; i < 5; i++) {
//       await new Promise(r => setTimeout(r, 2000));
//       const analysis = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } });
//       console.log(`File analysis attempt ${i + 1}:`, analysis.data.data.attributes.status);
//       if (analysis.data.data.attributes.status === 'completed') {
//         vtStats = analysis.data.data.attributes.stats;
//         vtFullData = analysis.data.data.attributes;
//         console.log('VirusTotal File Analysis Complete:', vtStats);
//         break;
//       }
//       if (i === 4) throw new Error('File analysis timed out');
//     }

//     const isSafe = vtStats.malicious === 0 && vtStats.suspicious === 0;
//     const safetyScore = vtFullData.reputation !== undefined
//       ? Math.round((vtFullData.reputation + 100) / 2)
//       : Math.round(((vtStats.harmless + vtStats.undetected) / (vtStats.harmless + vtStats.undetected + vtStats.malicious + vtStats.suspicious)) * 100) || 0;

//     const geminiData = await fetchGeminiData('File', file.originalname, vtStats, vtFullData);

//     let recordId = null;
//     try {
//       const { data, error } = await supabase.from('file_insights').insert([{ filename: file.originalname, is_safe: isSafe, safety_score: safetyScore, vt_stats: vtStats, vt_full_data: vtFullData, gemini_insights: geminiData }]).select();
//       if (error) throw error;
//       recordId = data[0].id;
//       console.log('File scan completed, record ID:', recordId);
//     } catch (supabaseError) {
//       console.error('Supabase Insert Error:', supabaseError.message);
//       console.log('Proceeding with response despite Supabase failure');
//     }

//     res.json({ isSafe, safetyScore, vtStats, vtFullData, geminiInsights: geminiData, recordId });
//   } catch (error) {
//     console.error('File Scan Error:', error.message, 'Response:', error.response?.data);
//     res.status(500).json({ error: `File scan failed: ${error.message}`, details: error.response?.data });
//   }
// });

// app.get('/api/insights', async (req, res) => {
//   try {
//     const { data, error } = await supabase
//       .from('scan_insights')
//       .select('*')
//       .order('created_at', { ascending: false });
//     if (error) throw error;
//     res.json(data);
//   } catch (error) {
//     console.error('Insights Fetch Error:', error.message);
//     res.status(500).json({ error: `Failed to fetch insights: ${error.message}` });
//   }
// });

// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));