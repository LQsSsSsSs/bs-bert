import { api } from './client'

export type PredictionRequest = {
  description: string
}

export type CweDetail = {
  label: string
  confidence: number
  info?: Record<string, unknown> | null
}

export type PredictionResponse = {
  vector: string
  base_score: number
  severity: string
  details: Record<string, unknown>
  cwe?: CweDetail | null
  translated_description?: string | null
  language: string
}

export type HistoryRow = {
  id: number
  timestamp: string
  original_description: string | null
  translated_description: string | null
  cvss_vector: string | null
  base_score: number | null
  severity: string | null
  source_ip: string | null
}

export async function predict(payload: PredictionRequest) {
  const { data } = await api.post<PredictionResponse>('/predict', payload)
  return data
}

export async function getHistory(limit = 10) {
  const { data } = await api.get<HistoryRow[]>('/history', { params: { limit } })
  return data
}

