const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'shopease_secret_key_2024';

// ─── Helpers ────────────────────────────────────────────────────────────────
const dbPath = (file) => path.join(__dirname, 'data', file);
const readDB = (file) => JSON.parse(fs.readFileSync(dbPath(file), 'utf8'));
const writeDB = (file, data) => fs.writeFileSync(dbPath(file), JSON.stringify(data, null, 2));

// ─── Middleware ──────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ─── Auth Routes ─────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, phone, address } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required' });

  const users = readDB('users.json');
  if (users.find(u => u.email === email)) return res.status(409).json({ error: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 10);
  const user = {
    id: Date.now(),
    name,
    email,
    password: hashed,
    phone: phone || '',
    address: address || '',
    role: users.length === 0 ? 'admin' : 'user', // first user becomes admin
    createdAt: new Date()
  };
  users.push(user);
  writeDB('users.json', users);

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, ...safeUser } = user;
  res.status(201).json({ token, user: safeUser });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  const users = readDB('users.json');
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

// ─── User Profile Routes ──────────────────────────────────────────────────────

// GET /api/profile  — get own profile
app.get('/api/profile', auth, (req, res) => {
  const users = readDB('users.json');
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password: _, ...safeUser } = user;
  res.json(safeUser);
});

// PUT /api/profile  — update own profile
app.put('/api/profile', auth, async (req, res) => {
  const { name, phone, address, password } = req.body;
  const users = readDB('users.json');
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });

  if (name) users[idx].name = name;
  if (phone !== undefined) users[idx].phone = phone;
  if (address !== undefined) users[idx].address = address;
  if (password) users[idx].password = await bcrypt.hash(password, 10);

  writeDB('users.json', users);
  const { password: _, ...safeUser } = users[idx];
  res.json(safeUser);
});

// ─── Admin: User Management ───────────────────────────────────────────────────

// GET /api/admin/users  — list all users (admin)
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = readDB('users.json').map(({ password: _, ...u }) => u);
  res.json(users);
});

// DELETE /api/admin/users/:id  — delete a user (admin)
app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  let users = readDB('users.json');
  const exists = users.find(u => u.id === parseInt(req.params.id));
  if (!exists) return res.status(404).json({ error: 'User not found' });
  users = users.filter(u => u.id !== parseInt(req.params.id));
  writeDB('users.json', users);
  res.json({ message: 'User deleted' });
});

// ─── Product Routes (CRUD) ────────────────────────────────────────────────────

// GET /api/products  — public
app.get('/api/products', (req, res) => {
  const { category, search } = req.query;
  let products = readDB('products.json');
  if (category && category !== 'All') products = products.filter(p => p.category === category);
  if (search) products = products.filter(p => p.name.toLowerCase().includes(search.toLowerCase()));
  res.json(products);
});

// GET /api/products/:id  — public
app.get('/api/products/:id', (req, res) => {
  const products = readDB('products.json');
  const product = products.find(p => p.id === parseInt(req.params.id));
  product ? res.json(product) : res.status(404).json({ error: 'Product not found' });
});

// POST /api/products  — admin only
app.post('/api/products', auth, adminOnly, (req, res) => {
  const { name, price, category, image, description, stock } = req.body;
  if (!name || !price || !category) return res.status(400).json({ error: 'name, price and category are required' });

  const products = readDB('products.json');
  const product = {
    id: Date.now(),
    name,
    price: parseFloat(price),
    category,
    image: image || 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=400',
    description: description || '',
    stock: parseInt(stock) || 0
  };
  products.push(product);
  writeDB('products.json', products);
  res.status(201).json(product);
});

// PUT /api/products/:id  — admin only
app.put('/api/products/:id', auth, adminOnly, (req, res) => {
  const products = readDB('products.json');
  const idx = products.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Product not found' });

  const { name, price, category, image, description, stock } = req.body;
  if (name) products[idx].name = name;
  if (price) products[idx].price = parseFloat(price);
  if (category) products[idx].category = category;
  if (image) products[idx].image = image;
  if (description !== undefined) products[idx].description = description;
  if (stock !== undefined) products[idx].stock = parseInt(stock);

  writeDB('products.json', products);
  res.json(products[idx]);
});

// DELETE /api/products/:id  — admin only
app.delete('/api/products/:id', auth, adminOnly, (req, res) => {
  let products = readDB('products.json');
  const exists = products.find(p => p.id === parseInt(req.params.id));
  if (!exists) return res.status(404).json({ error: 'Product not found' });
  products = products.filter(p => p.id !== parseInt(req.params.id));
  writeDB('products.json', products);
  res.json({ message: 'Product deleted' });
});

// GET /api/products/:id/similar  — similar products by category
app.get('/api/products/:id/similar', (req, res) => {
  const products = readDB('products.json');
  const product = products.find(p => p.id === parseInt(req.params.id));
  if (!product) return res.status(404).json({ error: 'Product not found' });
  const similar = products.filter(p => p.category === product.category && p.id !== product.id).slice(0, 4);
  res.json(similar);
});

// GET /api/products/:id/reviews  — get reviews
app.get('/api/products/:id/reviews', (req, res) => {
  const reviews = readDB('reviews.json');
  res.json(reviews.filter(r => r.productId === parseInt(req.params.id)));
});

// POST /api/products/:id/reviews  — add review (auth required)
app.post('/api/products/:id/reviews', auth, (req, res) => {
  const { rating, comment } = req.body;
  if (!rating || !comment) return res.status(400).json({ error: 'Rating and comment are required' });
  const reviews = readDB('reviews.json');
  const users = readDB('users.json');
  const user = users.find(u => u.id === req.user.id);
  const review = {
    id: Date.now(),
    productId: parseInt(req.params.id),
    userId: req.user.id,
    userName: user?.name || 'Anonymous',
    rating: parseInt(rating),
    comment,
    createdAt: new Date()
  };
  reviews.push(review);
  writeDB('reviews.json', reviews);
  res.status(201).json(review);
});

// DELETE /api/products/:id/reviews/:rid  — delete review (own or admin)
app.delete('/api/products/:id/reviews/:rid', auth, (req, res) => {
  let reviews = readDB('reviews.json');
  const review = reviews.find(r => r.id === parseInt(req.params.rid));
  if (!review) return res.status(404).json({ error: 'Review not found' });
  if (review.userId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  reviews = reviews.filter(r => r.id !== parseInt(req.params.rid));
  writeDB('reviews.json', reviews);
  res.json({ message: 'Review deleted' });
});


// POST /api/orders  — place order (auth required)
app.post('/api/orders', auth, (req, res) => {
  const { items, total, shippingAddress } = req.body;
  if (!items || !total) return res.status(400).json({ error: 'items and total are required' });

  const orders = readDB('orders.json');
  const order = {
    id: Date.now(),
    userId: req.user.id,
    items,
    total,
    shippingAddress: shippingAddress || '',
    status: 'confirmed',
    createdAt: new Date()
  };
  orders.push(order);
  writeDB('orders.json', orders);
  res.status(201).json({ message: 'Order placed successfully!', order });
});

// GET /api/orders  — get own orders
app.get('/api/orders', auth, (req, res) => {
  const orders = readDB('orders.json').filter(o => o.userId === req.user.id);
  res.json(orders);
});

// GET /api/orders/:id  — get single order (own or admin)
app.get('/api/orders/:id', auth, (req, res) => {
  const orders = readDB('orders.json');
  const order = orders.find(o => o.id === parseInt(req.params.id));
  if (!order) return res.status(404).json({ error: 'Order not found' });
  if (order.userId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  res.json(order);
});

// GET /api/admin/orders  — all orders (admin)
app.get('/api/admin/orders', auth, adminOnly, (req, res) => {
  res.json(readDB('orders.json'));
});

// PUT /api/admin/orders/:id  — update order status (admin)
app.put('/api/admin/orders/:id', auth, adminOnly, (req, res) => {
  const orders = readDB('orders.json');
  const idx = orders.findIndex(o => o.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Order not found' });
  orders[idx].status = req.body.status || orders[idx].status;
  writeDB('orders.json', orders);
  res.json(orders[idx]);
});

app.listen(5000, () => console.log('Server running on http://localhost:5000'));
