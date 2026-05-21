import React, { useEffect, useState } from 'react'
import { getFeedback } from '../api/client'

export default function FeedbackInsights({ sessionId, query = '' }) {
  const [insights, setInsights] = useState([])
  const [summary, setSummary] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchFeedback = async () => {
      try {
        const res = await getFeedback(sessionId)
        setInsights(res.data.insights || [])
        setSummary(res.data.summary || '')
      } catch (error) {
        console.error('Failed to fetch feedback:', error)
      } finally {
        setLoading(false)
      }
    }

    fetchFeedback()
  }, [sessionId])

  if (loading) return <div className="p-4 text-gray-500">Loading insights...</div>

  if (!insights || insights.length === 0) {
    return <div className="p-4 text-gray-500 italic">No feedback yet. Submit verdicts to see insights.</div>
  }

  return (
    <div className="p-4">
      <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">{summary}</p>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-gray-300 dark:border-gray-600">
              <th className="text-left py-2 px-2">Rule</th>
              <th className="text-right py-2 px-2">TP</th>
              <th className="text-right py-2 px-2">FP</th>
              <th className="text-right py-2 px-2">FP %</th>
              <th className="text-left py-2 px-2">Suggestion</th>
            </tr>
          </thead>
          <tbody>
            {insights.filter(i => !query || (i.rule_id || '').toLowerCase().includes(query.toLowerCase()) || (i.suggestion || '').toLowerCase().includes(query.toLowerCase())).map((insight) => (
              <tr key={insight.rule_id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-800">
                <td className="py-2 px-2 font-semibold text-blue-600 dark:text-blue-400">
                  {insight.rule_id}
                </td>
                <td className="text-right py-2 px-2 text-green-600 dark:text-green-400">
                  {insight.tp_count}
                </td>
                <td className="text-right py-2 px-2 text-red-600 dark:text-red-400">
                  {insight.fp_count}
                </td>
                <td className="text-right py-2 px-2">
                  <div className="inline-block w-20">
                    <div className="flex justify-between text-xs mb-1">
                      <span>{(insight.fp_rate * 100).toFixed(0)}%</span>
                    </div>
                    <div className="w-full bg-gray-300 dark:bg-gray-700 rounded-full h-1.5">
                      <div
                        className={`h-1.5 rounded-full ${
                          insight.fp_rate > 0.4 ? 'bg-red-500' : insight.fp_rate > 0.15 ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${insight.fp_rate * 100}%` }}
                      />
                    </div>
                  </div>
                </td>
                <td className="py-2 px-2 text-gray-600 dark:text-gray-400">
                  {insight.suggestion ? (
                    <span className="text-orange-600 dark:text-orange-400 font-semibold">
                      ⚠️ {insight.suggestion.substring(0, 40)}...
                    </span>
                  ) : (
                    <span className="text-green-600 dark:text-green-400">✓ Good</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {insights.some((i) => i.suggestion) && (
        <div className="mt-4 p-3 bg-orange-100 dark:bg-orange-900/30 border border-orange-300 dark:border-orange-700 rounded text-xs text-orange-900 dark:text-orange-200">
          <strong>Threshold Suggestions:</strong> Some rules have high false positive rates. Review and adjust detection thresholds to improve accuracy.
        </div>
      )}
    </div>
  )
}
