import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Plus, Trash2 } from 'lucide-react';
import {
  useAssets, createAsset, deleteAsset, useAssetCves, useAllAssetsCves, useKnownVendorProducts,
} from '../api/hooks';
import './AssetsPage.css';

function AddAssetForm({ onAdded }) {
  const [vendor, setVendor] = useState('');
  const [product, setProduct] = useState('');
  const [version, setVersion] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const { data: knownData } = useKnownVendorProducts();
  const known = knownData?.vendor_products || [];

  // Autocomplete against real graph data (design spec Decision 9) rather than free text --
  // a vendor/product typo that matches nothing in CPEMatch would silently never produce a
  // match, with no error to tell the user why.
  const vendors = [...new Set(known.map(kv => kv.vendor))];
  const productsForVendor = [...new Set(
    known.filter(kv => kv.vendor.toLowerCase() === vendor.toLowerCase()).map(kv => kv.product)
  )];

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!vendor || !product || !version) return;
    setSubmitting(true);
    try {
      await createAsset({ vendor, product, version });
      setVendor(''); setProduct(''); setVersion('');
      onAdded();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form className="add-asset-form" onSubmit={handleSubmit}>
      <input
        placeholder="Vendor (e.g. cisco)" value={vendor} list="vendor-options"
        onChange={e => setVendor(e.target.value)}
      />
      <datalist id="vendor-options">
        {vendors.map(v => <option key={v} value={v} />)}
      </datalist>

      <input
        placeholder="Product (e.g. ios xe)" value={product} list="product-options"
        onChange={e => setProduct(e.target.value)}
      />
      <datalist id="product-options">
        {productsForVendor.map(p => <option key={p} value={p} />)}
      </datalist>

      <input placeholder="Version (e.g. 17.3.1)" value={version} onChange={e => setVersion(e.target.value)} />
      <button className="btn btn--primary btn--sm" type="submit" disabled={submitting}>
        <Plus size={16} /> Add
      </button>
    </form>
  );
}

export default function AssetsPage() {
  const [selectedKey, setSelectedKey] = useState(null);
  const { data: assetsData, refetch: refetchAssets } = useAssets();
  const { data: assetCves } = useAssetCves(selectedKey);
  const { data: allCves } = useAllAssetsCves();

  const assets = assetsData?.assets || [];
  const cves = selectedKey ? (assetCves?.cves || []) : (allCves?.cves || []);

  const handleDelete = async (assetKey) => {
    await deleteAsset(assetKey);
    if (selectedKey === assetKey) setSelectedKey(null);
    refetchAssets();
  };

  return (
    <div className="assets-page fade-in">
      <div className="assets-sidebar">
        <div className="sidebar-header">
          <h2>Your Assets</h2>
        </div>
        <AddAssetForm onAdded={refetchAssets} />
        <div className="asset-cards">
          <div
            className={`asset-card card card--clickable ${selectedKey === null ? 'active' : ''}`}
            onClick={() => setSelectedKey(null)}
          >
            All assets
          </div>
          {assets.map(a => (
            <div
              key={a.asset_key}
              className={`asset-card card card--clickable ${selectedKey === a.asset_key ? 'active' : ''}`}
              onClick={() => setSelectedKey(a.asset_key)}
            >
              <h4>{a.name || `${a.vendor} ${a.product}`}</h4>
              <div className="asset-meta">
                <span>{a.vendor} / {a.product}</span>
                <span>v{a.version}</span>
              </div>
              <button className="btn btn--ghost" onClick={(e) => { e.stopPropagation(); handleDelete(a.asset_key); }}>
                <Trash2 size={16} />
              </button>
            </div>
          ))}
        </div>
      </div>

      <div className="assets-detail">
        <h3>{selectedKey ? 'Matched CVEs' : 'CVEs across all assets'}</h3>
        {cves.length === 0 ? (
          <div className="empty-state"><p>No matching CVEs.</p></div>
        ) : (
          <div className="cve-list">
            {cves.map(c => (
              <Link key={c.id} to={`/entity/cve/${c.id}`} className="card asset-cve-card">
                <h4>{c.cve_id}</h4>
                <p>{c.description}</p>
                <span className={`badge badge--${(c.severity_band || 'unknown').toLowerCase()}`}>
                  {c.severity_band || 'unknown'}
                </span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
