require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3001;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(cors());
app.use(express.json());

// JWT Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Role-based access
const requireRole = (role) => (req, res, next) => {
  if (req.user.role !== role) return res.status(403).json({ error: 'Access denied' });
  next();
};

// ============================================
// AUTH ROUTES
// ============================================

// Customer Register
app.post('/api/auth/register', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('firstName').notEmpty(),
  body('lastName').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  
  const { email, password, firstName, lastName, phone } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, first_name, last_name, phone) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, first_name, last_name',
      [email, hashedPassword, firstName, lastName, phone]
    );
    
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: 'customer' }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ token, user: { id: user.id, email: user.email, firstName: user.first_name, lastName: user.last_name } });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: err.message });
  }
});

// Login (Customer, Supplier, Admin)
app.post('/api/auth/login', async (req, res) => {
  const { email, password, type } = req.body;
  
  try {
    let result, user, role;
    
    if (type === 'supplier') {
      result = await pool.query('SELECT * FROM suppliers WHERE email = $1', [email]);
      if (result.rows.length === 0) return res.status(400).json({ error: 'Supplier not found' });
      user = result.rows[0];
      role = 'supplier';
    } else if (type === 'admin') {
      result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      if (result.rows.length === 0 || result.rows[0].email !== 'admin@buildbuy.co.za') {
        return res.status(400).json({ error: 'Admin not found' });
      }
      user = result.rows[0];
      role = 'admin';
    } else {
      result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      if (result.rows.length === 0) return res.status(400).json({ error: 'User not found' });
      user = result.rows[0];
      role = 'customer';
    }
    
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(400).json({ error: 'Invalid password' });
    
    const token = jwt.sign({ id: user.id, email: user.email, role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        email: user.email, 
        name: role === 'supplier' ? user.name : user.first_name + ' ' + user.last_name,
        role 
      } 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get current user
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    let result;
    if (req.user.role === 'supplier') {
      result = await pool.query('SELECT id, name, email, contact_person, phone FROM suppliers WHERE id = $1', [req.user.id]);
    } else {
      result = await pool.query('SELECT id, first_name, last_name, email, phone FROM users WHERE id = $1', [req.user.id]);
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// PRODUCTS & CATEGORIES
// ============================================

app.get('/api/categories', async (req, res) => {
  try {
    const categories = await pool.query('SELECT * FROM categories ORDER BY sort_order');
    res.json(categories.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/products', async (req, res) => {
  const { category, search, limit = 50 } = req.query;
  
  try {
    let query = `
      SELECT p.*, c.name as category_name, c.slug as category_slug,
        (SELECT MIN(price) FROM supplier_products WHERE product_id = p.id AND is_available = true AND stock_quantity > 0) as best_price
      FROM products p
      LEFT JOIN categories c ON p.category_id = c.id
      WHERE p.is_active = true
    `;
    const params = [];
    
    if (category) {
      params.push(category);
      query += ` AND c.slug = $${params.length}`;
    }
    
    if (search) {
      params.push(`%${search}%`);
      query += ` AND (p.name ILIKE $${params.length} OR p.brand ILIKE $${params.length})`;
    }
    
    query += ' ORDER BY p.created_at DESC';
    if (limit) {
      params.push(parseInt(limit));
      query += ` LIMIT $${params.length}`;
    }
    
    const products = await pool.query(query, params);
    res.json(products.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await pool.query(`
      SELECT p.*, c.name as category_name,
        json_agg(json_build_object(
          'supplier_id', s.id,
          'supplier_name', s.name,
          'price', sp.price,
          'stock', sp.stock_quantity,
          'available', sp.is_available
        ) ORDER BY sp.price) as supplier_prices
      FROM products p
      LEFT JOIN categories c ON p.category_id = c.id
      LEFT JOIN supplier_products sp ON sp.product_id = p.id AND sp.is_available = true AND sp.stock_quantity > 0
      LEFT JOIN suppliers s ON sp.supplier_id = s.id AND s.status = 'active'
      WHERE p.id = $1
      GROUP BY p.id, c.name
    `, [req.params.id]);
    
    if (product.rows.length === 0) return res.status(404).json({ error: 'Product not found' });
    res.json(product.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// COMPARISON ENGINE (CORE FEATURE)
// ============================================

app.post('/api/compare', authenticate, async (req, res) => {
  const { items, addressId, deliveryMethod } = req.body;
  
  try {
    const addressResult = await pool.query('SELECT * FROM addresses WHERE id = $1 AND user_id = $2', [addressId, req.user.id]);
    if (addressResult.rows.length === 0) return res.status(400).json({ error: 'Address not found' });
    const address = addressResult.rows[0];
    
    const suppliers = await pool.query("SELECT * FROM suppliers WHERE status = 'active'");
    
    const comparisons = [];
    
    for (const supplier of suppliers.rows) {
      let basketTotal = 0;
      let allAvailable = true;
      const itemDetails = [];
      
      for (const item of items) {
        const sp = await pool.query(
          'SELECT * FROM supplier_products WHERE supplier_id = $1 AND product_id = $2 AND is_available = true AND stock_quantity >= $3',
          [supplier.id, item.productId, item.qty]
        );
        
        if (sp.rows.length === 0) {
          allAvailable = false;
          break;
        }
        
        const price = sp.rows[0].price;
        const lineTotal = price * item.qty;
        basketTotal += lineTotal;
        
        const product = await pool.query('SELECT name, unit_type FROM products WHERE id = $1', [item.productId]);
        itemDetails.push({
          productId: item.productId,
          productName: product.rows[0].name,
          qty: item.qty,
          unitPrice: price,
          lineTotal: lineTotal,
          unit: product.rows[0].unit_type
        });
      }
      
      if (!allAvailable) continue;
      
      let deliveryCost = 0;
      let distance = 0;
      
      if (deliveryMethod === 'delivery') {
        distance = calculateDistance(
          supplier.latitude, supplier.longitude,
          address.latitude, address.longitude
        );
        
        if (distance > supplier.delivery_radius_km) continue;
        
        deliveryCost = Math.max(supplier.min_delivery_fee, distance * supplier.delivery_rate_per_km);
      }
      
      comparisons.push({
        supplier: {
          id: supplier.id,
          name: supplier.name,
          address: supplier.address,
          city: supplier.city,
          phone: supplier.phone
        },
        basketTotal: Math.round(basketTotal * 100) / 100,
        deliveryCost: Math.round(deliveryCost * 100) / 100,
        total: Math.round((basketTotal + deliveryCost) * 100) / 100,
        distance: Math.round(distance * 10) / 10,
        itemDetails
      });
    }
    
    comparisons.sort((a, b) => a.total - b.total);
    
    res.json({
      comparisons,
      winner: comparisons[0] || null,
      count: comparisons.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// ORDERS
// ============================================

app.post('/api/orders', authenticate, async (req, res) => {
  const { items, addressId, deliveryMethod, paymentMethod } = req.body;
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const addressResult = await client.query('SELECT * FROM addresses WHERE id = $1', [addressId]);
    const address = addressResult.rows[0];
    
    const suppliers = await client.query("SELECT * FROM suppliers WHERE status = 'active'");
    
    let winner = null;
    let allComparisons = [];
    
    for (const supplier of suppliers.rows) {
      let basketTotal = 0;
      let allAvailable = true;
      
      for (const item of items) {
        const sp = await client.query(
          'SELECT price FROM supplier_products WHERE supplier_id = $1 AND product_id = $2 AND is_available = true AND stock_quantity >= $3',
          [supplier.id, item.productId, item.qty]
        );
        if (sp.rows.length === 0) { allAvailable = false; break; }
        basketTotal += sp.rows[0].price * item.qty;
      }
      
      if (!allAvailable) continue;
      
      let deliveryCost = 0;
      let distance = 0;
      
      if (deliveryMethod === 'delivery') {
        distance = calculateDistance(supplier.latitude, supplier.longitude, address.latitude, address.longitude);
        if (distance > supplier.delivery_radius_km) continue;
        deliveryCost = Math.max(supplier.min_delivery_fee, distance * supplier.delivery_rate_per_km);
      }
      
      const total = basketTotal + deliveryCost;
      allComparisons.push({ supplier, basketTotal, deliveryCost, total, distance });
    }
    
    allComparisons.sort((a, b) => a.total - b.total);
    winner = allComparisons[0];
    
    if (!winner) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No supplier can fulfill this order' });
    }
    
    const orderNumber = 'BB-' + new Date().getFullYear() + '-' + Math.floor(1000 + Math.random() * 9000);
    const commissionAmount = (winner.basketTotal * winner.supplier.commission_percent) / 100;
    
    const orderResult = await client.query(`
      INSERT INTO orders (order_number, user_id, supplier_id, address_id, delivery_method, status,
        items_total, delivery_fee, total_amount, commission_amount, payment_method)
      VALUES ($1, $2, $3, $4, $5, 'pending_supplier', $6, $7, $8, $9, $10)
      RETURNING *
    `, [orderNumber, req.user.id, winner.supplier.id, addressId, deliveryMethod,
        winner.basketTotal, winner.deliveryCost, winner.total, commissionAmount, paymentMethod]);
    
    const order = orderResult.rows[0];
    
    for (const item of items) {
      const sp = await client.query(
        'SELECT price FROM supplier_products WHERE supplier_id = $1 AND product_id = $2',
        [winner.supplier.id, item.productId]
      );
      const price = sp.rows[0].price;
      await client.query(`
        INSERT INTO order_items (order_id, product_id, supplier_id, quantity, unit_price, total_price)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [order.id, item.productId, winner.supplier.id, item.qty, price, price * item.qty]);
    }
    
    for (const comp of allComparisons) {
      await client.query(`
        INSERT INTO order_comparisons (order_id, supplier_id, basket_total, delivery_cost, final_total, distance_km, is_winner)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [order.id, comp.supplier.id, comp.basketTotal, comp.deliveryCost, comp.total, comp.distance, comp.supplier.id === winner.supplier.id]);
    }
    
    await client.query(`
      INSERT INTO commissions (supplier_id, order_id, order_amount, commission_percent, commission_amount)
      VALUES ($1, $2, $3, $4, $5)
    `, [winner.supplier.id, order.id, winner.basketTotal, winner.supplier.commission_percent, commissionAmount]);
    
    await client.query('COMMIT');
    
    res.json({
      order: {
        id: order.id,
        orderNumber: order.order_number,
        status: order.status,
        total: order.total_amount,
        supplier: winner.supplier.name
      }
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/orders', authenticate, async (req, res) => {
  try {
    const orders = await pool.query(`
      SELECT o.*, s.name as supplier_name, s.phone as supplier_phone
      FROM orders o
      LEFT JOIN suppliers s ON o.supplier_id = s.id
      WHERE o.user_id = $1
      ORDER BY o.created_at DESC
    `, [req.user.id]);
    res.json(orders.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/orders/:id', authenticate, async (req, res) => {
  try {
    const order = await pool.query(`
      SELECT o.*, s.name as supplier_name, s.phone as supplier_phone, s.address as supplier_address,
        a.street_address, a.suburb, a.city, a.province
      FROM orders o
      LEFT JOIN suppliers s ON o.supplier_id = s.id
      LEFT JOIN addresses a ON o.address_id = a.id
      WHERE o.id = $1 AND o.user_id = $2
    `, [req.params.id, req.user.id]);
    
    if (order.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    
    const items = await pool.query(`
      SELECT oi.*, p.name as product_name, p.image_url, p.unit_type
      FROM order_items oi
      LEFT JOIN products p ON oi.product_id = p.id
      WHERE oi.order_id = $1
    `, [req.params.id]);
    
    const statusHistory = await pool.query(`
      SELECT * FROM order_status_history WHERE order_id = $1 ORDER BY created_at
    `, [req.params.id]);
    
    res.json({ ...order.rows[0], items: items.rows, statusHistory: statusHistory.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// SUPPLIER PORTAL ROUTES
// ============================================

app.get('/api/supplier/orders', authenticate, requireRole('supplier'), async (req, res) => {
  try {
    const orders = await pool.query(`
      SELECT o.*, u.first_name, u.last_name, u.phone as customer_phone
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      WHERE o.supplier_id = $1
      ORDER BY o.created_at DESC
    `, [req.user.id]);
    res.json(orders.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/supplier/orders/:id/status', authenticate, requireRole('supplier'), async (req, res) => {
  const { status, notes } = req.body;
  try {
    const orderCheck = await pool.query('SELECT * FROM orders WHERE id = $1 AND supplier_id = $2', [req.params.id, req.user.id]);
    if (orderCheck.rows.length === 0) return res.status(403).json({ error: 'Not your order' });
    
    await pool.query('UPDATE orders SET status = $1, supplier_notes = $2, updated_at = NOW() WHERE id = $3', [status, notes, req.params.id]);
    await pool.query('INSERT INTO order_status_history (order_id, status, notes, created_by) VALUES ($1, $2, $3, $4)', [req.params.id, status, notes, req.user.id]);
    
    res.json({ message: 'Status updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/supplier/products', authenticate, requireRole('supplier'), async (req, res) => {
  try {
    const products = await pool.query(`
      SELECT p.id as product_id, p.name, p.brand, p.sku, p.description, p.unit_type, p.image_url,
        c.name as category_name, c.slug as category_slug,
        sp.id as supplier_product_id, sp.price, sp.stock_quantity, sp.is_available, sp.last_updated
      FROM products p
      LEFT JOIN categories c ON p.category_id = c.id
      LEFT JOIN supplier_products sp ON sp.product_id = p.id AND sp.supplier_id = $1
      WHERE p.is_active = true
      ORDER BY c.sort_order, p.name
    `, [req.user.id]);
    res.json(products.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/supplier/products', authenticate, requireRole('supplier'), async (req, res) => {
  const { productId, price, stockQuantity, isAvailable } = req.body;
  try {
    const result = await pool.query(`
      INSERT INTO supplier_products (supplier_id, product_id, price, stock_quantity, is_available, last_updated)
      VALUES ($1, $2, $3, $4, $5, NOW())
      ON CONFLICT (supplier_id, product_id) 
      DO UPDATE SET price = EXCLUDED.price, stock_quantity = EXCLUDED.stock_quantity, 
        is_available = EXCLUDED.is_available, last_updated = NOW()
      RETURNING *
    `, [req.user.id, productId, price, stockQuantity, isAvailable]);
    res.json({ message: 'Product added/updated', product: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/supplier/products/:productId', authenticate, requireRole('supplier'), async (req, res) => {
  const { price, stockQuantity, isAvailable } = req.body;
  try {
    const result = await pool.query(`
      UPDATE supplier_products SET price = COALESCE($1, price), stock_quantity = COALESCE($2, stock_quantity), 
        is_available = COALESCE($3, is_available), last_updated = NOW()
      WHERE supplier_id = $4 AND product_id = $5 RETURNING *
    `, [price, stockQuantity, isAvailable, req.user.id, req.params.productId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Updated', product: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/supplier/products/bulk', authenticate, requireRole('supplier'), async (req, res) => {
  const { products } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const results = { success: 0, failed: 0, errors: [] };
    for (const item of products) {
      try {
        await client.query(`
          INSERT INTO supplier_products (supplier_id, product_id, price, stock_quantity, is_available, last_updated)
          VALUES ($1, $2, $3, $4, $5, NOW())
          ON CONFLICT (supplier_id, product_id) 
          DO UPDATE SET price = EXCLUDED.price, stock_quantity = EXCLUDED.stock_quantity, 
            is_available = EXCLUDED.is_available, last_updated = NOW()
        `, [req.user.id, item.productId, item.price, item.stockQuantity, item.isAvailable !== false]);
        results.success++;
      } catch (err) {
        results.failed++;
        results.errors.push(`${item.productId}: ${err.message}`);
      }
    }
    await client.query('COMMIT');
    res.json(results);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ============================================
// ADMIN ROUTES
// ============================================

app.get('/api/admin/orders', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const orders = await pool.query(`
      SELECT o.*, u.first_name, u.last_name, s.name as supplier_name
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN suppliers s ON o.supplier_id = s.id
      ORDER BY o.created_at DESC
    `);
    res.json(orders.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/orders/:id/comparisons', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const comparisons = await pool.query(`
      SELECT oc.*, s.name as supplier_name
      FROM order_comparisons oc
      LEFT JOIN suppliers s ON oc.supplier_id = s.id
      WHERE oc.order_id = $1
      ORDER BY oc.final_total
    `, [req.params.id]);
    res.json(comparisons.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/stats', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const totalOrders = await pool.query('SELECT COUNT(*) FROM orders');
    const totalSales = await pool.query('SELECT COALESCE(SUM(total_amount), 0) FROM orders WHERE status != $1', ['cancelled']);
    const totalSuppliers = await pool.query('SELECT COUNT(*) FROM suppliers WHERE status = $1', ['active']);
    const commissionEarned = await pool.query('SELECT COALESCE(SUM(commission_amount), 0) FROM commissions');
    
    const topSuppliers = await pool.query(`
      SELECT s.name, COALESCE(SUM(o.total_amount), 0) as sales
      FROM suppliers s
      LEFT JOIN orders o ON s.id = o.supplier_id AND o.status != 'cancelled'
      WHERE s.status = 'active'
      GROUP BY s.id, s.name
      ORDER BY sales DESC
      LIMIT 5
    `);
    
    res.json({
      totalOrders: parseInt(totalOrders.rows[0].count),
      totalSales: parseFloat(totalSales.rows[0].coalesce),
      totalSuppliers: parseInt(totalSuppliers.rows[0].count),
      commissionEarned: parseFloat(commissionEarned.rows[0].coalesce),
      topSuppliers: topSuppliers.rows
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/suppliers', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const suppliers = await pool.query('SELECT * FROM suppliers ORDER BY created_at DESC');
    res.json(suppliers.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// UTILITIES
// ============================================

function calculateDistance(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) + 
            Math.cos(lat1 * Math.PI/180) * Math.cos(lat2 * Math.PI/180) * 
            Math.sin(dLng/2) * Math.sin(dLng/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`BuildBuy API running on port ${PORT}`);
});