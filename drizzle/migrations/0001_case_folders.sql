CREATE TABLE public.case_folders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, name)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.case_folders TO authenticated;
GRANT ALL ON public.case_folders TO service_role;
ALTER TABLE public.case_folders ENABLE ROW LEVEL SECURITY;
CREATE POLICY case_folders_own ON public.case_folders FOR ALL TO authenticated
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

ALTER TABLE public.investigations
  ADD COLUMN folder_id uuid REFERENCES public.case_folders(id) ON DELETE SET NULL;
CREATE INDEX investigations_folder_idx ON public.investigations(folder_id);