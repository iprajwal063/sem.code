// backend/server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Model
const User = mongoose.model('User', {
  email: { type: String, unique: true },
  password: String,
  subscription: { type: String, enum: ['free', 'basic', 'pro'], default: 'free' },
  apiCalls: { type: Number, default: 0 },
  latestApiCall: Date
});

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Register Route
app.post('/api/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      email: req.body.email,
      password: hashedPassword
    });
    await user.save();
    res.status(201).json({ message: 'User created' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login Route
app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).json({ error: 'User not found' });
  
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const accessToken = jwt.sign({ email: user.email }, process.env.ACCESS_TOKEN_SECRET);
      res.json({ accessToken, subscription: user.subscription });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SEO Analysis Endpoint
app.post('/api/analyze', authenticateToken, async (req, res) => {
  try {
    const { url } = req.body;
    
    // Check user API limits
    const user = await User.findOne({ email: req.user.email });
    if (user.apiCalls >= 10 && user.subscription === 'free') {
      return res.status(429).json({ error: 'API limit reached. Upgrade for more.' });
    }
    
    // Fetch HTML
    const response = await axios.get(url);
    const html = response.data;
    const $ = cheerio.load(html);
    
    // Basic SEO metrics
    const title = $('title').text();
    const metaDescription = $('meta[name="description"]').attr('content');
    const headers = {
      h1: $('h1').map((i, el) => $(el).text()).get(),
      h2: $('h2').map((i, el) => $(el).text()).get()
    };
    
    // Keyword analysis (simplified)
    const text = $('body').text();
    const words = text.toLowerCase().match(/\b\w+\b/g) || [];
    const wordCount = words.length;
    const keywordDensity = words.reduce((acc, word) => {
      acc[word] = (acc[word] || 0) + 1;
      return acc;
    }, {});
    
    // Update user API call count
    user.apiCalls += 1;
    user.latestApiCall = new Date();
    await user.save();
    
    res.json({
      url,
      title,
      metaDescription,
      headers,
      wordCount,
      keywordDensity: Object.entries(keywordDensity)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20)
        .map(([word, count]) => ({ word, count, density: (count / wordCount * 100).toFixed(2) + '%' })),
      links: {
        internal: $('a[href^="/"], a[href^="' + new URL(url).origin + '"]').length,
        external: $('a').not('a[href^="/"], a[href^="' + new URL(url).origin + '"]').length,
        nofollow: $('a[rel="nofollow"]').length
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
