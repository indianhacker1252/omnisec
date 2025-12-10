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
    PostgrestVersion: "13.0.5"
  }
  public: {
    Tables: {
      security_audit_log: {
        Row: {
          action: string
          created_at: string | null
          id: string
          module: string | null
          result: string | null
          target: string | null
          user_id: string | null
        }
        Insert: {
          action: string
          created_at?: string | null
          id?: string
          module?: string | null
          result?: string | null
          target?: string | null
          user_id?: string | null
        }
        Update: {
          action?: string
          created_at?: string | null
          id?: string
          module?: string | null
          result?: string | null
          target?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          created_at: string | null
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string | null
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string | null
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
      vapt_config: {
        Row: {
          allowed_targets: string[] | null
          created_at: string
          id: string
          log_level: string | null
          mode: string
          operator_id: string | null
          updated_at: string
        }
        Insert: {
          allowed_targets?: string[] | null
          created_at?: string
          id?: string
          log_level?: string | null
          mode?: string
          operator_id?: string | null
          updated_at?: string
        }
        Update: {
          allowed_targets?: string[] | null
          created_at?: string
          id?: string
          log_level?: string | null
          mode?: string
          operator_id?: string | null
          updated_at?: string
        }
        Relationships: []
      }
      vapt_feedback: {
        Row: {
          action_id: string | null
          comments: string | null
          created_at: string
          id: string
          operator_id: string | null
          rating: string
          suggestion_id: string | null
        }
        Insert: {
          action_id?: string | null
          comments?: string | null
          created_at?: string
          id?: string
          operator_id?: string | null
          rating: string
          suggestion_id?: string | null
        }
        Update: {
          action_id?: string | null
          comments?: string | null
          created_at?: string
          id?: string
          operator_id?: string | null
          rating?: string
          suggestion_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "vapt_feedback_action_id_fkey"
            columns: ["action_id"]
            isOneToOne: false
            referencedRelation: "vapt_test_actions"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "vapt_feedback_suggestion_id_fkey"
            columns: ["suggestion_id"]
            isOneToOne: false
            referencedRelation: "vapt_suggestions"
            referencedColumns: ["id"]
          },
        ]
      }
      vapt_suggestions: {
        Row: {
          action_id: string | null
          created_at: string
          explanation: string
          id: string
          model_used: string | null
          payload_templates: Json | null
          strategies: Json
        }
        Insert: {
          action_id?: string | null
          created_at?: string
          explanation: string
          id?: string
          model_used?: string | null
          payload_templates?: Json | null
          strategies?: Json
        }
        Update: {
          action_id?: string | null
          created_at?: string
          explanation?: string
          id?: string
          model_used?: string | null
          payload_templates?: Json | null
          strategies?: Json
        }
        Relationships: [
          {
            foreignKeyName: "vapt_suggestions_action_id_fkey"
            columns: ["action_id"]
            isOneToOne: false
            referencedRelation: "vapt_test_actions"
            referencedColumns: ["id"]
          },
        ]
      }
      vapt_test_actions: {
        Row: {
          created_at: string
          domain: string | null
          embedding_text: string | null
          id: string
          injection_point: string | null
          method: string
          notes: string | null
          operator_id: string | null
          outcome_label: string | null
          payload_sent: string | null
          request_body: string | null
          request_headers: Json | null
          response_body: string | null
          response_headers: Json | null
          response_status: number | null
          target_url: string
          test_type: string
          transformed_payload: string | null
        }
        Insert: {
          created_at?: string
          domain?: string | null
          embedding_text?: string | null
          id?: string
          injection_point?: string | null
          method?: string
          notes?: string | null
          operator_id?: string | null
          outcome_label?: string | null
          payload_sent?: string | null
          request_body?: string | null
          request_headers?: Json | null
          response_body?: string | null
          response_headers?: Json | null
          response_status?: number | null
          target_url: string
          test_type: string
          transformed_payload?: string | null
        }
        Update: {
          created_at?: string
          domain?: string | null
          embedding_text?: string | null
          id?: string
          injection_point?: string | null
          method?: string
          notes?: string | null
          operator_id?: string | null
          outcome_label?: string | null
          payload_sent?: string | null
          request_body?: string | null
          request_headers?: Json | null
          response_body?: string | null
          response_headers?: Json | null
          response_status?: number | null
          target_url?: string
          test_type?: string
          transformed_payload?: string | null
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      find_similar_vapt_actions: {
        Args: {
          p_domain?: string
          p_injection_point?: string
          p_limit?: number
          p_operator_id: string
          p_search_text?: string
          p_test_type: string
        }
        Returns: {
          created_at: string
          id: string
          injection_point: string
          method: string
          notes: string
          outcome_label: string
          payload_sent: string
          similarity_score: number
          target_url: string
          test_type: string
        }[]
      }
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "analyst" | "viewer"
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
    Enums: {
      app_role: ["admin", "analyst", "viewer"],
    },
  },
} as const
