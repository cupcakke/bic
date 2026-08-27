export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.17"
  }
  public: {
    Tables: {
      agent_agents: {
        Row: {
          alias: string
          created_at: string
          depth: number
          id: string
          instruction: string
          parent_id: string | null
          result: Json | null
          role: string
          state: string
          task_id: string
          updated_at: string
          workspace_path: string | null
        }
        Insert: {
          alias: string
          created_at?: string
          depth?: number
          id?: string
          instruction: string
          parent_id?: string | null
          result?: Json | null
          role: string
          state?: string
          task_id: string
          updated_at?: string
          workspace_path?: string | null
        }
        Update: {
          alias?: string
          created_at?: string
          depth?: number
          id?: string
          instruction?: string
          parent_id?: string | null
          result?: Json | null
          role?: string
          state?: string
          task_id?: string
          updated_at?: string
          workspace_path?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "agent_agents_parent_id_fkey"
            columns: ["parent_id"]
            isOneToOne: false
            referencedRelation: "agent_agents"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "agent_agents_task_id_fkey"
            columns: ["task_id"]
            isOneToOne: false
            referencedRelation: "agent_tasks"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_artifacts: {
        Row: {
          agent_id: string | null
          content: string | null
          created_at: string
          id: string
          mime_type: string
          path: string
          sha256: string | null
          size_bytes: number
          task_id: string | null
        }
        Insert: {
          agent_id?: string | null
          content?: string | null
          created_at?: string
          id?: string
          mime_type?: string
          path: string
          sha256?: string | null
          size_bytes?: number
          task_id?: string | null
        }
        Update: {
          agent_id?: string | null
          content?: string | null
          created_at?: string
          id?: string
          mime_type?: string
          path?: string
          sha256?: string | null
          size_bytes?: number
          task_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "agent_artifacts_agent_id_fkey"
            columns: ["agent_id"]
            isOneToOne: false
            referencedRelation: "agent_agents"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "agent_artifacts_task_id_fkey"
            columns: ["task_id"]
            isOneToOne: false
            referencedRelation: "agent_tasks"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_audit: {
        Row: {
          action: string
          actor: string
          created_at: string
          detail: Json
          id: number
          target: string | null
        }
        Insert: {
          action: string
          actor: string
          created_at?: string
          detail?: Json
          id?: number
          target?: string | null
        }
        Update: {
          action?: string
          actor?: string
          created_at?: string
          detail?: Json
          id?: number
          target?: string | null
        }
        Relationships: []
      }
      agent_browser_sessions: {
        Row: {
          created_at: string
          current_url: string | null
          history: Json
          id: string
          sandbox_id: string | null
          status: string
          task_id: string | null
          updated_at: string
        }
        Insert: {
          created_at?: string
          current_url?: string | null
          history?: Json
          id?: string
          sandbox_id?: string | null
          status?: string
          task_id?: string | null
          updated_at?: string
        }
        Update: {
          created_at?: string
          current_url?: string | null
          history?: Json
          id?: string
          sandbox_id?: string | null
          status?: string
          task_id?: string | null
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "agent_browser_sessions_sandbox_id_fkey"
            columns: ["sandbox_id"]
            isOneToOne: false
            referencedRelation: "agent_sandboxes"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "agent_browser_sessions_task_id_fkey"
            columns: ["task_id"]
            isOneToOne: false
            referencedRelation: "agent_tasks"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_credentials: {
        Row: {
          ciphertext: string
          created_at: string
          id: string
          iv: string
          name: string
          updated_at: string
        }
        Insert: {
          ciphertext: string
          created_at?: string
          id?: string
          iv: string
          name: string
          updated_at?: string
        }
        Update: {
          ciphertext?: string
          created_at?: string
          id?: string
          iv?: string
          name?: string
          updated_at?: string
        }
        Relationships: []
      }
      agent_events: {
        Row: {
          agent_id: string | null
          created_at: string
          id: number
          kind: string
          payload: Json
          task_id: string | null
        }
        Insert: {
          agent_id?: string | null
          created_at?: string
          id?: number
          kind: string
          payload?: Json
          task_id?: string | null
        }
        Update: {
          agent_id?: string | null
          created_at?: string
          id?: number
          kind?: string
          payload?: Json
          task_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "agent_events_agent_id_fkey"
            columns: ["agent_id"]
            isOneToOne: false
            referencedRelation: "agent_agents"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "agent_events_task_id_fkey"
            columns: ["task_id"]
            isOneToOne: false
            referencedRelation: "agent_tasks"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_leases: {
        Row: {
          expires_at: string
          heartbeat_at: string
          name: string
          owner: string
        }
        Insert: {
          expires_at: string
          heartbeat_at?: string
          name: string
          owner: string
        }
        Update: {
          expires_at?: string
          heartbeat_at?: string
          name?: string
          owner?: string
        }
        Relationships: []
      }
      agent_mcp_servers: {
        Row: {
          auth_credential: string | null
          created_at: string
          id: string
          name: string
          status: string
          tools: Json
          transport: string
          updated_at: string
          url: string
        }
        Insert: {
          auth_credential?: string | null
          created_at?: string
          id?: string
          name: string
          status?: string
          tools?: Json
          transport?: string
          updated_at?: string
          url: string
        }
        Update: {
          auth_credential?: string | null
          created_at?: string
          id?: string
          name?: string
          status?: string
          tools?: Json
          transport?: string
          updated_at?: string
          url?: string
        }
        Relationships: []
      }
      agent_sandboxes: {
        Row: {
          created_at: string
          id: string
          metadata: Json
          provider: string
          remote_id: string | null
          status: string
          task_id: string | null
          updated_at: string
          workspace_path: string | null
        }
        Insert: {
          created_at?: string
          id?: string
          metadata?: Json
          provider?: string
          remote_id?: string | null
          status?: string
          task_id?: string | null
          updated_at?: string
          workspace_path?: string | null
        }
        Update: {
          created_at?: string
          id?: string
          metadata?: Json
          provider?: string
          remote_id?: string | null
          status?: string
          task_id?: string | null
          updated_at?: string
          workspace_path?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "agent_sandboxes_task_id_fkey"
            columns: ["task_id"]
            isOneToOne: false
            referencedRelation: "agent_tasks"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_sessions: {
        Row: {
          created_at: string
          external_key: string | null
          id: string
          label: string | null
          metadata: Json
          updated_at: string
        }
        Insert: {
          created_at?: string
          external_key?: string | null
          id?: string
          label?: string | null
          metadata?: Json
          updated_at?: string
        }
        Update: {
          created_at?: string
          external_key?: string | null
          id?: string
          label?: string | null
          metadata?: Json
          updated_at?: string
        }
        Relationships: []
      }
      agent_sources: {
        Row: {
          canonical_url: string
          created_at: string
          id: string
          provider: string
          published_at: string | null
          score: number | null
          snippet: string | null
          task_id: string | null
          title: string | null
          url: string
        }
        Insert: {
          canonical_url: string
          created_at?: string
          id?: string
          provider: string
          published_at?: string | null
          score?: number | null
          snippet?: string | null
          task_id?: string | null
          title?: string | null
          url: string
        }
        Update: {
          canonical_url?: string
          created_at?: string
          id?: string
          provider?: string
          published_at?: string | null
          score?: number | null
          snippet?: string | null
          task_id?: string | null
          title?: string | null
          url?: string
        }
        Relationships: [
          {
            foreignKeyName: "agent_sources_task_id_fkey"
            columns: ["task_id"]
            isOneToOne: false
            referencedRelation: "agent_tasks"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_tasks: {
        Row: {
          autonomous: boolean
          continuation_token: string | null
          created_at: string
          deleted_at: string | null
          error: Json | null
          final_response: string | null
          final_writer_alias: string | null
          heartbeat_at: string | null
          human_input: Json | null
          human_request: Json | null
          id: string
          idempotency_key: string | null
          lease_expires_at: string | null
          lease_owner: string | null
          objective: string
          phase: string
          priority: number
          scheduled_at: string
          session_id: string
          state: string
          state_data: Json
          success_criteria: Json
          trace_id: string
          updated_at: string
          version: number
        }
        Insert: {
          autonomous?: boolean
          continuation_token?: string | null
          created_at?: string
          deleted_at?: string | null
          error?: Json | null
          final_response?: string | null
          final_writer_alias?: string | null
          heartbeat_at?: string | null
          human_input?: Json | null
          human_request?: Json | null
          id?: string
          idempotency_key?: string | null
          lease_expires_at?: string | null
          lease_owner?: string | null
          objective: string
          phase?: string
          priority?: number
          scheduled_at?: string
          session_id: string
          state?: string
          state_data?: Json
          success_criteria?: Json
          trace_id: string
          updated_at?: string
          version?: number
        }
        Update: {
          autonomous?: boolean
          continuation_token?: string | null
          created_at?: string
          deleted_at?: string | null
          error?: Json | null
          final_response?: string | null
          final_writer_alias?: string | null
          heartbeat_at?: string | null
          human_input?: Json | null
          human_request?: Json | null
          id?: string
          idempotency_key?: string | null
          lease_expires_at?: string | null
          lease_owner?: string | null
          objective?: string
          phase?: string
          priority?: number
          scheduled_at?: string
          session_id?: string
          state?: string
          state_data?: Json
          success_criteria?: Json
          trace_id?: string
          updated_at?: string
          version?: number
        }
        Relationships: [
          {
            foreignKeyName: "agent_tasks_session_id_fkey"
            columns: ["session_id"]
            isOneToOne: false
            referencedRelation: "agent_sessions"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_tool_calls: {
        Row: {
          agent_id: string | null
          error: string | null
          finished_at: string | null
          id: string
          input: Json
          output: Json | null
          provider: string | null
          started_at: string
          status: string
          task_id: string | null
          tool: string
        }
        Insert: {
          agent_id?: string | null
          error?: string | null
          finished_at?: string | null
          id?: string
          input?: Json
          output?: Json | null
          provider?: string | null
          started_at?: string
          status?: string
          task_id?: string | null
          tool: string
        }
        Update: {
          agent_id?: string | null
          error?: string | null
          finished_at?: string | null
          id?: string
          input?: Json
          output?: Json | null
          provider?: string | null
          started_at?: string
          status?: string
          task_id?: string | null
          tool?: string
        }
        Relationships: [
          {
            foreignKeyName: "agent_tool_calls_agent_id_fkey"
            columns: ["agent_id"]
            isOneToOne: false
            referencedRelation: "agent_agents"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "agent_tool_calls_task_id_fkey"
            columns: ["task_id"]
            isOneToOne: false
            referencedRelation: "agent_tasks"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
