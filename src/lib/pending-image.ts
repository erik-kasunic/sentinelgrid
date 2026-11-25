// Hands an image dropped on the search box to /metadata, in memory only.
let pending: File | null = null;
export const setPendingImage = (f: File) => {
  pending = f;
};
export const takePendingImage = () => {
  const f = pending;
  pending = null;
  return f;
};
export const isImageFile = (f: File) =>
  f.type.startsWith("image/") ||
  /\.(jpe?g|png|heic|heif|dng|cr2|nef|arw|tiff?|webp)$/i.test(f.name);
