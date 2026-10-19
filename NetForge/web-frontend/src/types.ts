export interface ModuleParam {
  name: string
  type: string
  label: string
  required: boolean
  default: string | number | boolean | null
  description: string
}

export interface ModuleInfo {
  name: string
  description: string
  category: string
  parameters: ModuleParam[]
}

export interface RunResult {
  status: string
  packets_sent: number
  bytes_sent: number
  log_file: string | null
  error?: string
}
