import React from 'react'

const criticality_colors = {
  critical: 'bg-red-100 dark:bg-red-900/30 text-red-900 dark:text-red-200 border-red-300 dark:border-red-700',
  high: 'bg-orange-100 dark:bg-orange-900/30 text-orange-900 dark:text-orange-200 border-orange-300 dark:border-orange-700',
  medium: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-900 dark:text-yellow-200 border-yellow-300 dark:border-yellow-700',
  low: 'bg-green-100 dark:bg-green-900/30 text-green-900 dark:text-green-200 border-green-300 dark:border-green-700',
}

export default function AssetCard({ asset }) {
  if (!asset) return null

  const criticality = asset.criticality || 'medium'
  const colorClass = criticality_colors[criticality] || criticality_colors.medium

  return (
    <div className={`border-l-4 rounded-r p-3 mb-3 ${colorClass}`}>
      <div className="font-semibold text-sm mb-1">{asset.hostname || 'Unknown Host'}</div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <span className="font-semibold">Criticality:</span>
          <div className={`inline-block ml-1 px-2 py-1 rounded capitalize border ${colorClass}`}>
            {criticality}
          </div>
        </div>
        <div>
          <span className="font-semibold">OS:</span> {asset.os || 'Unknown'}
        </div>
        <div>
          <span className="font-semibold">Owner:</span> {asset.owner || '—'}
        </div>
        <div>
          <span className="font-semibold">Last Patched:</span> {asset.last_patched || '—'}
        </div>
        {asset.department && (
          <div className="col-span-2">
            <span className="font-semibold">Department:</span> {asset.department}
          </div>
        )}
      </div>
    </div>
  )
}
