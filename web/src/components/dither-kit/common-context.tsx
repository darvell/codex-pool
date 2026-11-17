"use client"

import { createContext, use } from "react"
import type { Seed } from "./palette"

export type TooltipItem = {
  name: string
  label: string
  value: number
  seed: Seed
  dimmed: boolean
}

export type CommonChart = {
  names: string[]
  labelOf: (name: string) => string
  seedOf: (name: string) => Seed
  selectedDataKey: string | null
  selectDataKey: (key: string | null) => void
  /** Transient legend-hover emphasis — spotlights one series (others dim)
   * while the pointer rests on its legend entry. Selection still wins. */
  focusDataKey: string | null
  setFocusDataKey: (key: string | null) => void
  hoverIndex: number | null
  heading: (index: number, labelKey?: string) => string | null
  itemsAt: (index: number) => TooltipItem[]
  ready: boolean
  tooltipLeft: number // clamped px for the floating tooltip
  tooltipTop: number // px relative to the hovered node
}

export const CommonChartContext = createContext<CommonChart | null>(null)

export function useCommonChart() {
  const ctx = use(CommonChartContext)
  if (!ctx) {
    throw new Error(
      "<Legend /> / <Tooltip /> must be used within a chart root."
    )
  }
  return ctx
}
