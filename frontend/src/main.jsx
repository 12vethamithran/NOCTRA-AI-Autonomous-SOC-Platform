import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
      {/* Toasts re-skinned to match the red/black brand. The previous slate
          + green palette clashed with the surface tokens defined in index.css. */}
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 3500,
          style: {
            background: 'rgba(20,20,22,0.95)',
            color: '#f4f4f5',
            border: '1px solid #2e2e35',
            borderRadius: 10,
            padding: '10px 14px',
            fontSize: 13,
            backdropFilter: 'blur(12px)',
            WebkitBackdropFilter: 'blur(12px)',
            boxShadow: '0 8px 28px rgba(0,0,0,0.45)',
          },
          success: {
            iconTheme: { primary: '#f43f5e', secondary: '#0c0c0e' },
            style: { borderColor: 'rgba(225,29,72,0.45)' },
          },
          error: {
            iconTheme: { primary: '#ff4d4d', secondary: '#0c0c0e' },
            style: { borderColor: 'rgba(239,68,68,0.55)' },
          },
        }}
      />
    </BrowserRouter>
  </React.StrictMode>
)
