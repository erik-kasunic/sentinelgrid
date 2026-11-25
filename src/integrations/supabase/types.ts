export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[];

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.5";
  };
  public: {
    Tables: {
      case_folders: {
        Row: {
          created_at: string;
          id: string;
          name: string;
          user_id: string;
        };
        Insert: {
          created_at?: string;
          id?: string;
          name: string;
          user_id: string;
        };
        Update: {
          created_at?: string;
          id?: string;
          name?: string;
          user_id?: string;
        };
        Relationships: [];
      };
      evidence: {
        Row: {
          confidence: number | null;
          created_at: string;
          detail: string | null;
          id: string;
          investigation_id: string;
          label: string;
          observed_at: string | null;
          provider: string;
          severity: string;
          source_url: string | null;
          user_id: string;
        };
        Insert: {
          confidence?: number | null;
          created_at?: string;
          detail?: string | null;
          id?: string;
          investigation_id: string;
          label: string;
          observed_at?: string | null;
          provider: string;
          severity?: string;
          source_url?: string | null;
          user_id: string;
        };
        Update: {
          confidence?: number | null;
          created_at?: string;
          detail?: string | null;
          id?: string;
          investigation_id?: string;
          label?: string;
          observed_at?: string | null;
          provider?: string;
          severity?: string;
          source_url?: string | null;
          user_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "evidence_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
        ];
      };
      investigation_iocs: {
        Row: {
          created_at: string;
          id: string;
          investigation_id: string;
          ioc_type: string;
          is_primary: boolean;
          user_id: string;
          value: string;
        };
        Insert: {
          created_at?: string;
          id?: string;
          investigation_id: string;
          ioc_type: string;
          is_primary?: boolean;
          user_id: string;
          value: string;
        };
        Update: {
          created_at?: string;
          id?: string;
          investigation_id?: string;
          ioc_type?: string;
          is_primary?: boolean;
          user_id?: string;
          value?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigation_iocs_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
        ];
      };
      investigations: {
        Row: {
          created_at: string;
          folder_id: string | null;
          id: string;
          initial_target: string;
          recommended_action: string | null;
          result: Json;
          summary: string | null;
          target_type: string;
          threat_score: number | null;
          title: string;
          updated_at: string;
          user_id: string;
          verdict: string;
          verdict_basis: string;
        };
        Insert: {
          created_at?: string;
          folder_id?: string | null;
          id?: string;
          initial_target: string;
          recommended_action?: string | null;
          result?: Json;
          summary?: string | null;
          target_type: string;
          threat_score?: number | null;
          title: string;
          updated_at?: string;
          user_id: string;
          verdict: string;
          verdict_basis?: string;
        };
        Update: {
          created_at?: string;
          folder_id?: string | null;
          id?: string;
          initial_target?: string;
          recommended_action?: string | null;
          result?: Json;
          summary?: string | null;
          target_type?: string;
          threat_score?: number | null;
          title?: string;
          updated_at?: string;
          user_id?: string;
          verdict?: string;
          verdict_basis?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigations_folder_id_fkey";
            columns: ["folder_id"];
            isOneToOne: false;
            referencedRelation: "case_folders";
            referencedColumns: ["id"];
          },
        ];
      };
      lookup_cache: {
        Row: {
          cache_key: string;
          fetched_at: string;
          result: Json;
          ttl_seconds: number;
        };
        Insert: {
          cache_key: string;
          fetched_at?: string;
          result: Json;
          ttl_seconds: number;
        };
        Update: {
          cache_key?: string;
          fetched_at?: string;
          result?: Json;
          ttl_seconds?: number;
        };
        Relationships: [];
      };
      profiles: {
        Row: {
          created_at: string;
          display_name: string | null;
          id: string;
          updated_at: string;
        };
        Insert: {
          created_at?: string;
          display_name?: string | null;
          id: string;
          updated_at?: string;
        };
        Update: {
          created_at?: string;
          display_name?: string | null;
          id?: string;
          updated_at?: string;
        };
        Relationships: [];
      };
      provider_results: {
        Row: {
          created_at: string;
          duration_ms: number | null;
          id: string;
          investigation_id: string;
          message: string | null;
          provider: string;
          status: string;
          user_id: string;
        };
        Insert: {
          created_at?: string;
          duration_ms?: number | null;
          id?: string;
          investigation_id: string;
          message?: string | null;
          provider: string;
          status: string;
          user_id: string;
        };
        Update: {
          created_at?: string;
          duration_ms?: number | null;
          id?: string;
          investigation_id?: string;
          message?: string | null;
          provider?: string;
          status?: string;
          user_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "provider_results_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
        ];
      };
      provider_usage: {
        Row: {
          created_at: string;
          id: number;
          provider: string;
        };
        Insert: {
          created_at?: string;
          id?: number;
          provider: string;
        };
        Update: {
          created_at?: string;
          id?: number;
          provider?: string;
        };
        Relationships: [];
      };
      rate_events: {
        Row: {
          created_at: string;
          id: number;
          ip_hash: string;
          kind: string;
        };
        Insert: {
          created_at?: string;
          id?: number;
          ip_hash: string;
          kind?: string;
        };
        Update: {
          created_at?: string;
          id?: number;
          ip_hash?: string;
          kind?: string;
        };
        Relationships: [];
      };
      relationships: {
        Row: {
          created_at: string;
          from_type: string;
          from_value: string;
          id: string;
          investigation_id: string;
          kind: string;
          to_type: string;
          to_value: string;
          user_id: string;
        };
        Insert: {
          created_at?: string;
          from_type: string;
          from_value: string;
          id?: string;
          investigation_id: string;
          kind: string;
          to_type: string;
          to_value: string;
          user_id: string;
        };
        Update: {
          created_at?: string;
          from_type?: string;
          from_value?: string;
          id?: string;
          investigation_id?: string;
          kind?: string;
          to_type?: string;
          to_value?: string;
          user_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "relationships_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
        ];
      };
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      [_ in never]: never;
    };
    Enums: {
      [_ in never]: never;
    };
    CompositeTypes: {
      [_ in never]: never;
    };
  };
};

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">;

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">];

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R;
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] & DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R;
      }
      ? R
      : never
    : never;

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    keyof DefaultSchema["Tables"] | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I;
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I;
      }
      ? I
      : never
    : never;

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    keyof DefaultSchema["Tables"] | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U;
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U;
      }
      ? U
      : never
    : never;

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    keyof DefaultSchema["Enums"] | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never;

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    keyof DefaultSchema["CompositeTypes"] | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never;

export const Constants = {
  public: {
    Enums: {},
  },
} as const;
